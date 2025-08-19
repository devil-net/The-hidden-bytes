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
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Steganography Analysis API", "status": "running"}

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
async def analyze_binwalk(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file.flush()
            
            # Run binwalk analysis
            result = subprocess.run(
                ["binwalk", temp_file.name],
                capture_output=True,
                text=True
            )
            
            analysis = []
            if result.stdout:
                lines = result.stdout.strip().split('\n')[3:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            offset = int(parts[0])
                            type_desc = ' '.join(parts[2:])
                            analysis.append({
                                "offset": offset,
                                "type": parts[1] if len(parts) > 1 else "Unknown",
                                "description": type_desc
                            })
            
            # Run binwalk extraction
            extract_result = subprocess.run(
                ["binwalk", "-e", temp_file.name],
                capture_output=True,
                text=True,
                cwd=tempfile.gettempdir()
            )
            
            extracted_files = []
            if extract_result.returncode == 0:
                # Look for extracted directory
                base_name = os.path.basename(temp_file.name)
                extract_dir = os.path.join(tempfile.gettempdir(), f"_{base_name}.extracted")
                if os.path.exists(extract_dir):
                    for root, dirs, files in os.walk(extract_dir):
                        for file_name in files:
                            file_path = os.path.join(root, file_name)
                            file_size = os.path.getsize(file_path)
                            extracted_files.append({
                                "name": file_name,
                                "size": file_size,
                                "path": os.path.relpath(file_path, extract_dir)
                            })
            
            os.unlink(temp_file.name)
            
            return {
                "success": True,
                "output": result.stdout,
                "analysis": analysis,
                "extracted_files": extracted_files,
                "extraction_output": extract_result.stdout,
                "extraction_error": extract_result.stderr if extract_result.returncode != 0 else None
            }
            
    except Exception as e:
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
            # Return RGBA values for first few pixels
            rgba_values = []
            for y in range(min(10, height)):
                for x in range(min(10, width)):
                    pixel = img_array[y, x]
                    rgba_values.append([int(pixel[0]), int(pixel[1]), int(pixel[2]), 255])
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
                "image_base64": f"data:image/png;base64,{img_base64}",
                "dimensions": {"width": width, "height": height}
            }
        
        else:  # original
            buffer = BytesIO()
            image.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                "success": True,
                "image_base64": f"data:image/png;base64,{img_base64}",
                "dimensions": {"width": width, "height": height}
            }
            
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/metadata")
async def analyze_metadata(file: UploadFile = File(...)):
    try:
        content = await file.read()
        image = Image.open(BytesIO(content))
        
        metadata = {}
        
        # Basic image info
        metadata["Format"] = image.format
        metadata["Mode"] = image.mode
        metadata["Size"] = f"{image.width}x{image.height}"
        
        # EXIF data
        if hasattr(image, '_getexif') and image._getexif():
            exif = image._getexif()
            for tag_id, value in exif.items():
                try:
                    from PIL.ExifTags import TAGS
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[str(tag)] = str(value)
                except:
                    pass
        
        # File info
        metadata["File Size"] = f"{len(content)} bytes"
        
        return {"success": True, "metadata": metadata}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
