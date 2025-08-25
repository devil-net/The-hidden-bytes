from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import subprocess
import tempfile
import os
import json
from PIL import Image
import numpy as np
import base64
from io import BytesIO
import re

app = FastAPI(title="Steganography Analysis API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "https://*.vercel.app",
        "https://vercel.app",
        "*"  # Allow all origins for now - restrict in production
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Steganography Analysis API", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": "2025-01-01"}

@app.post("/steghide")
async def analyze_steghide(file: UploadFile = File(...), password: str = Form("")):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file.flush()
            
            cmd = ["steghide", "extract", "-sf", temp_file.name, "-f"]
            if password:
                cmd.extend(["-p", password])
            else:
                cmd.extend(["-p", ""])
            
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=tempfile.gettempdir())
            
            os.unlink(temp_file.name)
            
            if result.returncode == 0:
                return {"success": True, "output": result.stdout or "Data extracted successfully"}
            else:
                return {"success": False, "error": result.stderr or "No hidden data found"}
                
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/binwalk")
async def analyze_binwalk(file: UploadFile = File(...), extract: str = Form("false")):
    try:
        # Create a dedicated working directory
        work_dir = tempfile.mkdtemp(prefix="binwalk_")
        
        # Save file with original extension if possible
        file_ext = ".bin"
        if file.filename and "." in file.filename:
            file_ext = "." + file.filename.split(".")[-1]
        
        temp_file_path = os.path.join(work_dir, f"analysis{file_ext}")
        
        content = await file.read()
        with open(temp_file_path, 'wb') as temp_file:
            temp_file.write(content)
        
        # Run binwalk analysis
        result = subprocess.run(
            ["binwalk", temp_file_path],
            capture_output=True,
            text=True,
            cwd=work_dir
        )
        
        analysis = []
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            # Skip header lines and empty lines
            for line in lines:
                if line.strip() and not line.startswith('DECIMAL') and not line.startswith('---'):
                    parts = line.split(None, 2)  # Split into max 3 parts
                    if len(parts) >= 2:
                        try:
                            offset = int(parts[0])
                            type_info = parts[1] if len(parts) > 1 else "Unknown"
                            description = parts[2] if len(parts) > 2 else ""
                            analysis.append({
                                "offset": offset,
                                "type": type_info,
                                "description": description
                            })
                        except ValueError:
                            # Skip lines that don't start with a number
                            continue
        
        extracted_files = []
        extraction_output = ""
        extraction_error = None
        
        # Only run extraction if explicitly requested
        if extract.lower() == "true":
            try:
                # Run binwalk extraction with specific options
                extract_result = subprocess.run(
                    ["binwalk", "-e", "--run-as=any", temp_file_path],
                    capture_output=True,
                    text=True,
                    cwd=work_dir,
                    timeout=60
                )
                
                extraction_output = extract_result.stdout
                
                if extract_result.returncode != 0:
                    extraction_error = extract_result.stderr
                else:
                    # Look for extracted directory
                    base_name = os.path.basename(temp_file_path)
                    extract_dir = os.path.join(work_dir, f"_{base_name}.extracted")
                    
                    if os.path.exists(extract_dir):
                        for root, dirs, files in os.walk(extract_dir):
                            for file_name in files:
                                file_path = os.path.join(root, file_name)
                                try:
                                    file_size = os.path.getsize(file_path)
                                    rel_path = os.path.relpath(file_path, extract_dir)
                                    extracted_files.append({
                                        "name": file_name,
                                        "size": file_size,
                                        "path": rel_path
                                    })
                                except OSError:
                                    # Skip files that can't be accessed
                                    continue
                    
                    if not extracted_files and not extraction_error:
                        extraction_error = "No files were extracted. The file may not contain embedded data."
                        
            except subprocess.TimeoutExpired:
                extraction_error = "Extraction timed out after 60 seconds."
            except Exception as extract_ex:
                extraction_error = f"Extraction failed: {str(extract_ex)}"
        
        # Clean up
        try:
            import shutil
            shutil.rmtree(work_dir)
        except Exception:
            # If cleanup fails, continue anyway
            pass
        
        return {
            "success": True,
            "output": result.stdout,
            "analysis": analysis,
            "extracted_files": extracted_files,
            "extraction_output": extraction_output,
            "extraction_error": extraction_error
        }
        
    except Exception as e:
        # Clean up on error
        try:
            import shutil
            if 'work_dir' in locals():
                shutil.rmtree(work_dir)
        except Exception:
            pass
        return {"success": False, "error": str(e)}

@app.post("/strings")
async def analyze_strings(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file.flush()
            
            result = subprocess.run(
                ["strings", temp_file.name],
                capture_output=True,
                text=True
            )
            
            os.unlink(temp_file.name)
            
            if result.returncode == 0:
                strings_list = [s.strip() for s in result.stdout.split('\n') if s.strip()]
                return {"success": True, "strings": strings_list}
            else:
                return {"success": False, "error": result.stderr}
                
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/rgb")
async def analyze_rgb(file: UploadFile = File(...), mode: str = "original", bit: int = 0, channel: str = "red"):
    try:
        content = await file.read()
        image = Image.open(BytesIO(content))
        
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        img_array = np.array(image)
        height, width = img_array.shape[:2]
        
        if mode == "rgba_values":
            # Return RGBA values for more pixels
            rgba_values = []
            sample_size = min(50, height * width)  # Sample more pixels
            count = 0
            for y in range(height):
                for x in range(width):
                    if count >= sample_size:
                        break
                    pixel = img_array[y, x]
                    rgba_values.append([int(pixel[0]), int(pixel[1]), int(pixel[2]), 255])
                    count += 1
                if count >= sample_size:
                    break
            return {
                "success": True,
                "rgba_values": rgba_values,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "bit_plane":
            # Extract specific bit plane
            channel_idx = {"red": 0, "green": 1, "blue": 2}[channel]
            bit_plane = (img_array[:, :, channel_idx] >> bit) & 1
            bit_plane = bit_plane * 255  # Convert to visible
            
            # Convert to base64
            bit_image = Image.fromarray(bit_plane.astype(np.uint8), mode='L')
            buffer = BytesIO()
            bit_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "red":
            # Show only red channel
            red_image = img_array.copy()
            red_image[:, :, 1] = 0  # Remove green
            red_image[:, :, 2] = 0  # Remove blue
            
            result_image = Image.fromarray(red_image)
            buffer = BytesIO()
            result_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "green":
            # Show only green channel
            green_image = img_array.copy()
            green_image[:, :, 0] = 0  # Remove red
            green_image[:, :, 2] = 0  # Remove blue
            
            result_image = Image.fromarray(green_image)
            buffer = BytesIO()
            result_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "blue":
            # Show only blue channel
            blue_image = img_array.copy()
            blue_image[:, :, 0] = 0  # Remove red
            blue_image[:, :, 1] = 0  # Remove green
            
            result_image = Image.fromarray(blue_image)
            buffer = BytesIO()
            result_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "inverse":
            # Invert RGB values
            inverse_image = 255 - img_array
            
            result_image = Image.fromarray(inverse_image)
            buffer = BytesIO()
            result_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        elif mode == "lsb_half":
            # Extract LSB and amplify
            lsb_image = img_array & 1  # Get LSB
            lsb_image = lsb_image * 255  # Amplify to visible range
            
            result_image = Image.fromarray(lsb_image.astype(np.uint8))
            buffer = BytesIO()
            result_image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
        
        else:  # original
            buffer = BytesIO()
            image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": img_base64,
                "dimensions": {"width": width, "height": height}
            }
            
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/metadata")
async def analyze_metadata(file: UploadFile = File(...)):
    try:
        content = await file.read()
        
        # Save to temporary file for exiftool analysis
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file.filename.split('.')[-1] if '.' in file.filename else 'jpg'}") as temp_file:
            temp_file.write(content)
            temp_file.flush()
            
            metadata = {}
            
            # Try to open with PIL for basic info
            try:
                image = Image.open(BytesIO(content))
                
                # Basic image info
                metadata["Basic Info"] = {
                    "Format": image.format or "Unknown",
                    "Mode": image.mode,
                    "Dimensions": f"{image.width}x{image.height}",
                    "File Size": f"{len(content):,} bytes ({len(content)/1024:.2f} KB)"
                }
                
                # EXIF data using PIL
                exif_data = {}
                if hasattr(image, '_getexif') and image._getexif():
                    from PIL.ExifTags import TAGS, GPSTAGS
                    exif = image._getexif()
                    for tag_id, value in exif.items():
                        try:
                            tag = TAGS.get(tag_id, f"Unknown_{tag_id}")
                            if tag == "GPSInfo":
                                gps_data = {}
                                for gps_tag_id, gps_value in value.items():
                                    gps_tag = GPSTAGS.get(gps_tag_id, f"GPS_{gps_tag_id}")
                                    gps_data[gps_tag] = str(gps_value)
                                exif_data[tag] = gps_data
                            else:
                                exif_data[tag] = str(value)[:200]  # Limit length
                        except Exception:
                            exif_data[f"Tag_{tag_id}"] = str(value)[:200]
                
                if exif_data:
                    metadata["EXIF Data"] = exif_data
                
                # Additional PIL info
                if hasattr(image, 'info') and image.info:
                    metadata["Image Info"] = {k: str(v)[:200] for k, v in image.info.items()}
                    
            except Exception as pil_error:
                metadata["Basic Info"] = {
                    "Error": f"Could not read image with PIL: {str(pil_error)}",
                    "File Size": f"{len(content):,} bytes ({len(content)/1024:.2f} KB)"
                }
            
            # Try exiftool for comprehensive metadata
            try:
                exiftool_result = subprocess.run(
                    ["exiftool", "-json", "-all", temp_file.name],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if exiftool_result.returncode == 0 and exiftool_result.stdout:
                    exiftool_data = json.loads(exiftool_result.stdout)[0]
                    # Remove file path for security
                    exiftool_data.pop("SourceFile", None)
                    metadata["Comprehensive Metadata (ExifTool)"] = exiftool_data
                    
            except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
                # ExifTool not available or failed
                pass
            except Exception:
                pass
            
            # Try strings command for hidden text
            try:
                strings_result = subprocess.run(
                    ["strings", "-n", "4", temp_file.name],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                if strings_result.returncode == 0 and strings_result.stdout:
                    strings_list = [s.strip() for s in strings_result.stdout.split('\n') if s.strip() and len(s.strip()) >= 4]
                    # Filter interesting strings
                    interesting_strings = []
                    for s in strings_list[:100]:  # Limit to first 100
                        if any(keyword in s.lower() for keyword in ['flag', 'password', 'key', 'secret', 'hidden', 'ctf', 'user', 'admin']):
                            interesting_strings.append(s)
                    
                    if interesting_strings:
                        metadata["Interesting Strings"] = interesting_strings[:20]  # Limit to 20
                    
                    # Show first 20 strings regardless
                    metadata["Sample Strings"] = strings_list[:20]
                    
            except Exception:
                pass
            
            # File signature analysis
            try:
                with open(temp_file.name, 'rb') as f:
                    header = f.read(32)
                    
                file_signatures = {
                    b'\xFF\xD8\xFF': 'JPEG',
                    b'\x89PNG\r\n\x1a\n': 'PNG',
                    b'GIF87a': 'GIF87a',
                    b'GIF89a': 'GIF89a',
                    b'BM': 'BMP',
                    b'RIFF': 'RIFF (WebP/AVI)',
                    b'\x00\x00\x01\x00': 'ICO',
                    b'PK\x03\x04': 'ZIP/JAR',
                    b'\x1f\x8b\x08': 'GZIP',
                    b'%PDF': 'PDF'
                }
                
                detected_type = "Unknown"
                for sig, file_type in file_signatures.items():
                    if header.startswith(sig):
                        detected_type = file_type
                        break
                
                metadata["File Analysis"] = {
                    "Detected Type": detected_type,
                    "Header (hex)": header.hex()[:64],
                    "Header (ascii)": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header)
                }
                
            except Exception:
                pass
            
            # Clean up
            os.unlink(temp_file.name)
            
            return {"success": True, "metadata": metadata}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

