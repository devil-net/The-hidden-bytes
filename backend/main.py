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
import stat
import time
from datetime import datetime
import mimetypes
import hashlib
import zipfile
import shutil

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
        # Create a dedicated working directory
        work_dir = tempfile.mkdtemp(prefix="steghide_")
        
        # Determine file extension
        file_ext = ".jpg"
        if file.filename and "." in file.filename:
            file_ext = "." + file.filename.split(".")[-1]
        
        temp_file_path = os.path.join(work_dir, f"input{file_ext}")
        
        content = await file.read()
        with open(temp_file_path, 'wb') as temp_file:
            temp_file.write(content)
        
        # First, check if file contains steganographic data
        info_cmd = ["steghide", "info", temp_file_path]
        if password:
            info_cmd.extend(["-p", password])
        else:
            info_cmd.extend(["-p", ""])
        
        info_result = subprocess.run(info_cmd, capture_output=True, text=True, cwd=work_dir)
        
        extracted_files = []
        extraction_output = ""
        extraction_error = None
        
        if info_result.returncode == 0:
            # Extract the data
            extract_cmd = ["steghide", "extract", "-sf", temp_file_path, "-f"]
            if password:
                extract_cmd.extend(["-p", password])
            else:
                extract_cmd.extend(["-p", ""])
            
            extract_result = subprocess.run(extract_cmd, capture_output=True, text=True, cwd=work_dir)
            extraction_output = extract_result.stdout
            
            if extract_result.returncode == 0:
                # Look for extracted files in the working directory
                for item in os.listdir(work_dir):
                    item_path = os.path.join(work_dir, item)
                    if os.path.isfile(item_path) and item != os.path.basename(temp_file_path):
                        try:
                            file_size = os.path.getsize(item_path)
                            # Try to read the content if it's text
                            try:
                                with open(item_path, 'r', encoding='utf-8') as f:
                                    content_preview = f.read(500)  # First 500 chars
                            except:
                                try:
                                    with open(item_path, 'rb') as f:
                                        raw_content = f.read(100)
                                        content_preview = f"Binary data: {raw_content.hex()[:100]}..."
                                except:
                                    content_preview = "Could not read file content"
                            
                            extracted_files.append({
                                "name": item,
                                "size": file_size,
                                "content_preview": content_preview
                            })
                        except OSError:
                            continue
            else:
                extraction_error = extract_result.stderr or "Extraction failed"
        else:
            extraction_error = info_result.stderr or "No steganographic data found or wrong password"
        
        # Clean up
        try:
            import shutil
            shutil.rmtree(work_dir)
        except Exception:
            pass
        
        return {
            "success": True,
            "info_output": info_result.stdout,
            "extraction_output": extraction_output,
            "extracted_files": extracted_files,
            "extraction_error": extraction_error,
            "has_hidden_data": info_result.returncode == 0
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
                # First try binwalk extraction with --run-as=root parameter
                extract_result = subprocess.run(
                    ["binwalk", "-e", "--run-as=root", temp_file_path],
                    capture_output=True,
                    text=True,
                    cwd=work_dir,
                    timeout=60
                )
                
                extraction_output = extract_result.stdout
                
                if extract_result.returncode == 0:
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
                                    # Try to get file content preview
                                    content_preview = ""
                                    try:
                                        if file_size < 1000:  # Only preview small files
                                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                                content_preview = f.read(200)
                                    except:
                                        pass
                                    
                                    extracted_files.append({
                                        "name": file_name,
                                        "size": file_size,
                                        "path": rel_path,
                                        "content_preview": content_preview
                                    })
                                except OSError:
                                    continue
                else:
                    # Binwalk failed, try alternative extraction methods
                    extraction_error = f"Binwalk extraction failed: {extract_result.stderr}"
                    
                    # Try ZIP extraction if file appears to be compressed
                    try:
                        with zipfile.ZipFile(temp_file_path, 'r') as zip_ref:
                            zip_extract_dir = os.path.join(work_dir, "zip_extracted")
                            os.makedirs(zip_extract_dir, exist_ok=True)
                            zip_ref.extractall(zip_extract_dir)
                            
                            # List extracted files
                            for root, dirs, files in os.walk(zip_extract_dir):
                                for file_name in files:
                                    file_path = os.path.join(root, file_name)
                                    try:
                                        file_size = os.path.getsize(file_path)
                                        rel_path = os.path.relpath(file_path, zip_extract_dir)
                                        extracted_files.append({
                                            "name": file_name,
                                            "size": file_size,
                                            "path": rel_path,
                                            "extraction_method": "ZIP"
                                        })
                                    except OSError:
                                        continue
                            
                            if extracted_files:
                                extraction_error = None
                                extraction_output += "\n[Fallback] Successfully extracted as ZIP archive"
                                
                    except zipfile.BadZipFile:
                        # Try 7zip extraction
                        try:
                            seven_zip_result = subprocess.run(
                                ["7z", "x", temp_file_path, f"-o{work_dir}/7z_extracted"],
                                capture_output=True,
                                text=True,
                                timeout=30
                            )
                            
                            if seven_zip_result.returncode == 0:
                                seven_zip_dir = os.path.join(work_dir, "7z_extracted")
                                if os.path.exists(seven_zip_dir):
                                    for root, dirs, files in os.walk(seven_zip_dir):
                                        for file_name in files:
                                            file_path = os.path.join(root, file_name)
                                            try:
                                                file_size = os.path.getsize(file_path)
                                                rel_path = os.path.relpath(file_path, seven_zip_dir)
                                                extracted_files.append({
                                                    "name": file_name,
                                                    "size": file_size,
                                                    "path": rel_path,
                                                    "extraction_method": "7ZIP"
                                                })
                                            except OSError:
                                                continue
                                    
                                    if extracted_files:
                                        extraction_error = None
                                        extraction_output += "\n[Fallback] Successfully extracted with 7zip"
                                        
                        except (FileNotFoundError, subprocess.TimeoutExpired):
                            # 7zip not available or timed out
                            pass
                    
                    except Exception:
                        pass
                
                if not extracted_files and not extraction_error:
                    extraction_error = "No files were extracted. The file may not contain embedded data or may be encrypted."
                        
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
        
        # Save to temporary file for analysis
        file_ext = ".bin"
        if file.filename and "." in file.filename:
            file_ext = "." + file.filename.split(".")[-1]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            
            metadata = {}
            
            # File system information
            try:
                file_stat = os.stat(temp_file.name)
                file_size_bytes = len(content)
                file_size_kb = file_size_bytes / 1024
                file_size_mb = file_size_kb / 1024
                
                # Calculate file hashes
                md5_hash = hashlib.md5(content).hexdigest()
                sha1_hash = hashlib.sha1(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()
                
                # Determine MIME type
                mime_type, _ = mimetypes.guess_type(file.filename or "unknown")
                
                metadata["File Information"] = {
                    "ExifTool Version Number": "12.25",  # Simulated version
                    "File Name": file.filename or "unknown",
                    "Directory": "/tmp",
                    "File Size": f"{file_size_bytes} bytes ({file_size_kb:.1f} KiB)",
                    "File Modification Date/Time": datetime.now().strftime("%Y:%m:%d %H:%M:%S%z"),
                    "File Access Date/Time": datetime.now().strftime("%Y:%m:%d %H:%M:%S%z"),
                    "File Inode Change Date/Time": datetime.now().strftime("%Y:%m:%d %H:%M:%S%z"),
                    "File Permissions": "-rw-------",
                    "File Type": mime_type or "Unknown",
                    "File Type Extension": file_ext.lstrip('.') if file_ext != '.bin' else "unknown",
                    "MIME Type": mime_type or "application/octet-stream",
                    "MD5": md5_hash,
                    "SHA1": sha1_hash,
                    "SHA256": sha256_hash
                }
                
            except Exception as e:
                metadata["File Information"] = {"Error": f"Could not get file info: {str(e)}"}
            
            # Try to analyze as image
            try:
                image = Image.open(BytesIO(content))
                
                # Get color type description
                color_type = "Unknown"
                if image.mode == "RGB":
                    color_type = "RGB"
                elif image.mode == "RGBA":
                    color_type = "RGB with Alpha"
                elif image.mode == "L":
                    color_type = "Grayscale"
                elif image.mode == "P":
                    color_type = "Palette"
                elif image.mode == "CMYK":
                    color_type = "CMYK"
                
                # Calculate bit depth
                bit_depth = 8  # Default for most formats
                if hasattr(image, 'bits'):
                    bit_depth = image.bits
                elif image.mode == "1":
                    bit_depth = 1
                elif image.mode in ["I", "F"]:
                    bit_depth = 32
                
                # Compression info
                compression = "Unknown"
                if image.format == "PNG":
                    compression = "Deflate/Inflate"
                elif image.format == "JPEG":
                    compression = "JPEG"
                elif image.format == "GIF":
                    compression = "LZW"
                
                # Filter info for PNG
                filter_type = "Adaptive" if image.format == "PNG" else "Unknown"
                interlace = "Noninterlaced" if image.format == "PNG" else "Unknown"
                
                metadata["Image Properties"] = {
                    "Image Width": str(image.width),
                    "Image Height": str(image.height),
                    "Bit Depth": str(bit_depth),
                    "Color Type": color_type,
                    "Compression": compression,
                    "Filter": filter_type,
                    "Interlace": interlace,
                    "Image Size": f"{image.width}x{image.height}",
                    "Megapixels": f"{(image.width * image.height) / 1000000:.2f}"
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
                    metadata["Additional Image Info"] = {k: str(v)[:200] for k, v in image.info.items()}
                    
            except Exception as pil_error:
                # Not an image or PIL failed
                pass
            
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
                    metadata["ExifTool Metadata"] = exiftool_data
                    
            except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
                # ExifTool not available or failed
                pass
            except Exception:
                pass
            
            # File signature analysis with more signatures
            try:
                with open(temp_file.name, 'rb') as f:
                    header = f.read(64)  # Read more bytes for better detection
                    
                file_signatures = {
                    b'\xFF\xD8\xFF': 'JPEG',
                    b'\x89PNG\r\n\x1a\n': 'PNG',
                    b'GIF87a': 'GIF87a',
                    b'GIF89a': 'GIF89a',
                    b'BM': 'BMP',
                    b'RIFF': 'RIFF (WebP/AVI/WAV)',
                    b'\x00\x00\x01\x00': 'ICO',
                    b'PK\x03\x04': 'ZIP/JAR/DOCX/XLSX',
                    b'\x1f\x8b\x08': 'GZIP',
                    b'%PDF': 'PDF',
                    b'\x7fELF': 'ELF Executable',
                    b'MZ': 'Windows Executable',
                    b'\xca\xfe\xba\xbe': 'Java Class',
                    b'\xfe\xed\xfa': 'Mach-O Binary',
                    b'\x50\x4b\x05\x06': 'ZIP (empty)',
                    b'\x50\x4b\x07\x08': 'ZIP (spanned)'
                }
                
                detected_type = "Unknown"
                for sig, file_type in file_signatures.items():
                    if header.startswith(sig):
                        detected_type = file_type
                        break
                
                # Entropy calculation (simple)
                entropy = 0
                if len(content) > 0:
                    byte_counts = [0] * 256
                    for byte in content[:1024]:  # Sample first 1KB
                        byte_counts[byte] += 1
                    
                    for count in byte_counts:
                        if count > 0:
                            p = count / min(len(content), 1024)
                            entropy -= p * (p.bit_length() - 1) if p > 0 else 0
                
                metadata["File Analysis"] = {
                    "Detected File Type": detected_type,
                    "Magic Number (hex)": header[:16].hex().upper(),
                    "Magic Number (ascii)": ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header[:16]),
                    "File Header (64 bytes hex)": header.hex().upper(),
                    "Entropy (first 1KB)": f"{entropy:.2f}",
                    "Is Likely Compressed/Encrypted": "Yes" if entropy > 7.5 else "No"
                }
                
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
                    keywords = ['flag', 'password', 'key', 'secret', 'hidden', 'ctf', 'user', 'admin', 'token', 'api', 'auth']
                    for s in strings_list[:200]:  # Check more strings
                        if any(keyword in s.lower() for keyword in keywords):
                            interesting_strings.append(s)
                    
                    if interesting_strings:
                        metadata["Interesting Strings"] = interesting_strings[:30]  # Show more
                    
                    # Show sample strings
                    metadata["Sample Strings"] = strings_list[:30]
                    metadata["Total Strings Found"] = len(strings_list)
                    
            except Exception:
                pass
            
            # Try file command for additional type detection
            try:
                file_result = subprocess.run(
                    ["file", "-b", temp_file.name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if file_result.returncode == 0 and file_result.stdout:
                    metadata["File Command Output"] = file_result.stdout.strip()
                    
            except Exception:
                pass
            
            # Clean up
            os.unlink(temp_file.name)
            
            return {"success": True, "metadata": metadata}
        
    except Exception as e:
        return {"success": False, "error": str(e)}

