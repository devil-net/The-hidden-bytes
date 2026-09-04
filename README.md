# The Hidden Bytes (V2)

A browser-local digital forensics, firmware carving, and steganography analysis suite.

The Hidden Bytes V2 runs **100% client-side** inside your browser RAM using WebAssembly (WASM), Web Workers, and native browser APIs. No files, passphrases, or evidence ever leave your machine.

---

## Features & Tools

- **Steghide Engine**: In-memory inspection and passphrase-authenticated payload extraction for JPEG, BMP, and WAV.
- **Binwalk Firmware Carver**: Deep file signature scanning, container offset detection, and in-browser ZIP, GZIP, and raw ZLIB stream decompression.
- **Strings & Flag Scanner**: Fast streaming byte scanner across ASCII, UTF-8, and UTF-16 with automatic CTF flag (`flag{...}`) and URL detection.
- **Zsteg Steganography Engine**: 15-channel color permutation testing (Red, Green, Blue, Alpha) in LSB/MSB planes with automated hidden ZLIB stream inflation.
- **RGB Viewer & Bit Panels**: Channel decomposition (Red, Green, Blue, Inverted, LSB Half), 8-bit plane selector (Bits 0-7), statistical LSB ratio metrics, and raw RGBA pixel inspector.
- **Metadata Explorer**: Zero-network parsing for EXIF, GPS location coordinates, XMP, IPTC, PNG text chunks, PDF dictionaries, and ID3 audio tags.
- **Shannon Entropy Mapping**: Block-by-block entropy calculation ($H(X) \in [0.0, 8.0]$) mapping encrypted and compressed payload regions.
- **Findings Correlator & Client-Side Extraction**: Synthesizes findings across multiple tools and generates single-file and multi-file ZIP downloads directly in browser memory.

---

## Quick Start

### Prerequisites
- Node.js 18+
- npm

### Installation & Local Run

```bash
# 1. Install dependencies
npm install

# 2. Start local development server
npm run dev
```

Open `http://localhost:5173` or `http://localhost:3000` in your browser.

- Live Demo: https://thehiddenbytes.vercel.app

---

## Testing & Verification

```bash
# Run unit and parity test suites
npm run test:engine

# Test production build
npm run build
```

---

## Deployment

The Hidden Bytes V2 is a pure static single-page application (SPA). It can be deployed to Vercel, Netlify, Cloudflare Pages, or GitHub Pages with zero server backend infrastructure.

- **Framework**: Vite
- **Build Command**: `npm run build`
- **Output Directory**: `dist`

---

## License

This project is open source and available under the MIT License.
