from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import subprocess
import os
import tempfile
import shutil
from typing import Dict, Any
# import magic  # Removed due to Windows compatibility issues
from PIL import Image
import io
import base64

app = FastAPI(title="Stegno - Image Analysis Tool")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create temp directory for file processing
TEMP_DIR = tempfile.mkdtemp()

def check_system_tool(tool_name: str) -> bool:
    try:
        subprocess.run([tool_name, "--version"], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False

@app.on_event("startup")
async def startup_event():
    # Check for required system tools
    required_tools = {
        "steghide": "Steghide is required for steganography analysis",
        "binwalk": "Binwalk is required for file analysis",
        "strings": "Strings is required for string extraction"
    }
    
    missing_tools = []
    for tool, message in required_tools.items():
        if not check_system_tool(tool):
            missing_tools.append(f"{tool}: {message}")
    
    if missing_tools:
        print("WARNING: Missing system tools:")
        for tool in missing_tools:
            print(f"- {tool}")

@app.post("/api/analyze/steghide")
async def analyze_steghide(file: UploadFile = File(...), password: str = None):
    try:
        # Save uploaded file
        temp_path = os.path.join(TEMP_DIR, file.filename)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Always pass -p (password or empty string)
        cmd = ["steghide", "extract", "-sf", temp_path, "-p", password or ""]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return {
            "success": result.returncode == 0,
            "output": result.stdout,
            "error": result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/api/analyze/binwalk")
async def analyze_binwalk(file: UploadFile = File(...), extract: bool = False):
    temp_path = None
    extract_dir = None
    try:
        # Create a unique temporary directory for this request
        request_temp_dir = os.path.join(TEMP_DIR, f"binwalk_{os.urandom(8).hex()}")
        os.makedirs(request_temp_dir, exist_ok=True)
        
        # Save uploaded file
        temp_path = os.path.join(request_temp_dir, file.filename)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Run binwalk analysis
        analysis_result = subprocess.run(["binwalk", temp_path], capture_output=True, text=True)
        
        # Parse the analysis output
        analysis_lines = analysis_result.stdout.splitlines()
        analysis_data = []
        for line in analysis_lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        offset = int(parts[0], 16)
                        analysis_data.append({
                            "offset": offset,
                            "type": parts[1],
                            "description": " ".join(parts[2:])
                        })
                    except ValueError:
                        continue

        result = {
            "success": analysis_result.returncode == 0,
            "analysis": analysis_data,
            "error": analysis_result.stderr
        }

        # If extraction is requested
        if extract and analysis_result.returncode == 0:
            extract_dir = os.path.join(request_temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            
            # Run binwalk extraction with more verbose output and better error handling
            try:
                extract_result = subprocess.run(
                    ["binwalk", "--extract", "--directory", extract_dir, temp_path],
                    capture_output=True,
                    text=True,
                    timeout=60  # 60 second timeout
                )
                
                if extract_result.returncode != 0:
                    result["extraction_error"] = extract_result.stderr or "Extraction failed"
                    result["extraction_output"] = extract_result.stdout
                    return result
                
                # Get list of extracted files with better error handling
                extracted_files = []
                try:
                    for root, _, files in os.walk(extract_dir):
                        for file_name in files:
                            try:
                                file_path = os.path.join(root, file_name)
                                relative_path = os.path.relpath(file_path, extract_dir)
                                file_size = os.path.getsize(file_path)
                                extracted_files.append({
                                    "name": relative_path,
                                    "size": file_size,
                                    "path": file_path
                                })
                            except (OSError, IOError) as e:
                                print(f"Error processing extracted file {file_name}: {e}")
                                continue
                except Exception as e:
                    result["extraction_error"] = f"Error listing extracted files: {str(e)}"
                
                result["extracted_files"] = extracted_files
                result["extraction_output"] = extract_result.stdout
                result["extraction_error"] = extract_result.stderr
                
            except subprocess.TimeoutExpired:
                result["extraction_error"] = "Extraction timed out after 60 seconds"
            except Exception as e:
                result["extraction_error"] = f"Extraction failed: {str(e)}"

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temporary files and directories
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
            if extract_dir and os.path.exists(extract_dir):
                shutil.rmtree(extract_dir)
            if request_temp_dir and os.path.exists(request_temp_dir):
                shutil.rmtree(request_temp_dir)
        except Exception as e:
            print(f"Error cleaning up temporary files: {e}")

@app.post("/api/analyze/strings")
async def analyze_strings(file: UploadFile = File(...)):
    try:
        temp_path = os.path.join(TEMP_DIR, file.filename)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        result = subprocess.run(["strings", temp_path], capture_output=True, text=True)
        
        return {
            "success": True,
            "strings": result.stdout.splitlines()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.post("/api/analyze/rgb")
async def analyze_rgb(
    file: UploadFile = File(...),
    mode: str = "original",
    bit: int = 0,
    channel: str = "red"
):
    try:
        contents = await file.read()
        img = Image.open(io.BytesIO(contents))
        if img.mode != 'RGB':
            img = img.convert('RGB')
        width, height = img.size
        r, g, b = img.split()
        result = {"success": True, "dimensions": {"width": width, "height": height}}

        def img_to_base64(pil_img):
            buf = io.BytesIO()
            pil_img.save(buf, format='PNG')
            return base64.b64encode(buf.getvalue()).decode('utf-8')

        if mode == "original":
            result["image_base64"] = img_to_base64(img)
        elif mode == "red":
            red_img = Image.merge('RGB', (r, Image.new('L', img.size), Image.new('L', img.size)))
            result["image_base64"] = img_to_base64(red_img)
        elif mode == "green":
            green_img = Image.merge('RGB', (Image.new('L', img.size), g, Image.new('L', img.size)))
            result["image_base64"] = img_to_base64(green_img)
        elif mode == "blue":
            blue_img = Image.merge('RGB', (Image.new('L', img.size), Image.new('L', img.size), b))
            result["image_base64"] = img_to_base64(blue_img)
        elif mode == "inverse":
            inv_img = Image.eval(img, lambda x: 255 - x)
            result["image_base64"] = img_to_base64(inv_img)
        elif mode == "lsb_half":
            # Zero out the upper 4 bits, keep only LSB 4 bits
            def lsb_half(channel_img):
                return channel_img.point(lambda x: (x & 0x0F) << 4)
            lsb_img = Image.merge('RGB', (lsb_half(r), lsb_half(g), lsb_half(b)))
            result["image_base64"] = img_to_base64(lsb_img)
        elif mode == "bit_plane":
            # Extract a specific bit plane for a channel
            ch = {'red': r, 'green': g, 'blue': b}[channel]
            plane = ch.point(lambda x: 255 if (x >> bit) & 1 else 0)
            plane_img = Image.merge('RGB', (plane if channel=='red' else Image.new('L', img.size),
                                            plane if channel=='green' else Image.new('L', img.size),
                                            plane if channel=='blue' else Image.new('L', img.size)))
            result["image_base64"] = img_to_base64(plane_img)
        elif mode == "rgba_values":
            # Return RGBA values as a list
            rgba_img = img.convert('RGBA')
            result["rgba_values"] = list(rgba_img.getdata())
        else:
            return {"success": False, "error": "Unknown mode"}
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/metadata")
async def analyze_metadata(file: UploadFile = File(...)):
    try:
        temp_path = os.path.join(TEMP_DIR, file.filename)
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = subprocess.run(["exiftool", "-j", temp_path], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            import json
            metadata = json.loads(result.stdout)[0] if result.stdout else {}
        else:
            metadata = {}
        return {
            "success": result.returncode == 0,
            "metadata": metadata,
            "error": result.stderr
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 