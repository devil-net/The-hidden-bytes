# The Hidden Bytes 🔍

A modern steganography analysis tool built for CTF enthusiasts and digital forensics. This web application provides an intuitive interface for analyzing images and files to uncover hidden data using various steganographic techniques.

## Features

- **Steghide Analysis**: Extract hidden data from images with password support
- **Binwalk Integration**: Scan and extract embedded files from binaries
- **String Extraction**: Find readable text within binary files
- **RGB/Bit Plane Analysis**: Visualize color channels and LSB data
- **Metadata Extraction**: View EXIF and other metadata information
- **Responsive Design**: Works seamlessly on mobile, tablet, and desktop

## Tools Included

### 🖼️ Steghide
Extract hidden files embedded in images using steganography. Supports password-protected extractions.

### 🔧 Binwalk
Firmware analysis tool for identifying and extracting embedded files within other files.

### 📝 Strings
Extract printable character sequences from binary files to find hidden text data.

### 🎨 RGB Viewer (Bit Panels)
Analyze least significant bits (LSB) and color channels to reveal hidden steganographic data.

### 📋 Metadata
Extract and display metadata information from images including EXIF data.

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- System tools: `steghide`, `binwalk`, `strings`, `exiftool`

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/devil-net/The-hidden-bytes.git
   cd The-hidden-bytes
   ```

2. **Backend Setup**
   ```bash
   cd backend
   pip install -r requirements.txt
   python main.py
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

4. **Access the application**
   - Live Demo: https://thehiddenbytes.vercel.app
## Usage

1. **Upload an Image**: Drag and drop or click to select an image file
2. **Choose Analysis Tool**: Select from Steghide, Binwalk, Strings, RGB Viewer, or Metadata
3. **Enter Password** (for Steghide): If the hidden data is password-protected
4. **Analyze**: Click the tool tab to start analysis
5. **View Results**: Examine the extracted data, files, or analysis results

## Live Demo

🚀 **Try it now**: [https://thehiddenbytes.vercel.app](https://thehiddenbytes.vercel.app)

## Deployment

This project is optimized for Vercel deployment. The frontend is deployed as a static site.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Author

Built by [devil-net](https://github.com/devil-net) for the CTF and digital forensics community.
