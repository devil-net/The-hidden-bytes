/**
 * The Hidden Bytes V2 - Engine & Analyzer Unit Tests
 */

import { describe, it, expect } from 'vitest';
import { StringsAnalyzer } from '../analyzers/strings';
import { SignatureAnalyzer } from '../analyzers/signatures';
import { EntropyAnalyzer } from '../analyzers/entropy';
import { BinwalkAnalyzer } from '../analyzers/binwalk';
import { MetadataAnalyzer } from '../analyzers/metadata';
import { parseJpegStream } from '../analyzers/metadata/jpeg';
import { analyzeStegoHints } from '../analyzers/metadata/stegoHints';
import { computeChannelStatistics } from '../analyzers/metadata/channelStats';
import { VirtualFileSystem } from '../vfs';
import { zipSync } from 'fflate';

describe('V2 Engine Core', () => {
  it('VirtualFileSystem correctly writes, reads, and enforces quotas', () => {
    const vfs = new VirtualFileSystem({ maxTotalBytes: 1024 * 1024, maxFileBytes: 512 * 1024 });
    const data = new Uint8Array([1, 2, 3, 4, 5]);

    vfs.writeFile('/workspace/input/test.bin', data);
    expect(vfs.exists('/workspace/input/test.bin')).toBe(true);

    const read = vfs.readFile('/workspace/input/test.bin');
    expect(read).toEqual(data);

    const files = vfs.listFiles('/workspace/input');
    expect(files.length).toBe(1);
    expect(files[0].name).toBe('test.bin');

    vfs.removeFile('/workspace/input/test.bin');
    expect(vfs.exists('/workspace/input/test.bin')).toBe(false);
  });

  it('StringsAnalyzer extracts printable ASCII and detects CTF flags', async () => {
    const analyzer = new StringsAnalyzer();
    const encoder = new TextEncoder();

    // Create binary with embedded flag and random bytes
    const textPart1 = encoder.encode('Some header text\n');
    const flagPart = encoder.encode('CTF{browser_wasm_stego_victory}\n');
    const randomBytes = new Uint8Array([0x00, 0x01, 0xFF, 0xFE, 0x02]);

    const combined = new Uint8Array(textPart1.length + randomBytes.length + flagPart.length);
    combined.set(textPart1, 0);
    combined.set(randomBytes, textPart1.length);
    combined.set(flagPart, textPart1.length + randomBytes.length);

    const result = await analyzer.run(combined);
    expect(result.success).toBe(true);
    expect(result.data?.strings).toContain('Some header text');
    expect(result.data?.strings).toContain('CTF{browser_wasm_stego_victory}');

    const flagFinding = result.findings.find(f => f.type === 'FLAG_DETECTED');
    expect(flagFinding).toBeDefined();
    expect(flagFinding?.description).toContain('CTF{browser_wasm_stego_victory}');
  });

  it('SignatureAnalyzer detects PNG header and trailing appended overlay', async () => {
    const analyzer = new SignatureAnalyzer();

    // PNG header (8 bytes) + IEND trailer (8 bytes) + trailing overlay (10 bytes)
    const pngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const iendChunk = [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    const trailingData = new TextEncoder().encode('SECRET_OVERLAY');

    const fileBytes = new Uint8Array(pngHeader.length + iendChunk.length + trailingData.length);
    fileBytes.set(pngHeader, 0);
    fileBytes.set(iendChunk, pngHeader.length);
    fileBytes.set(trailingData, pngHeader.length + iendChunk.length);

    const result = await analyzer.run(fileBytes);
    expect(result.success).toBe(true);

    const overlayFinding = result.findings.find(f => f.type === 'TRAILING_OVERLAY');
    expect(overlayFinding).toBeDefined();
    expect(overlayFinding?.metadata?.overlayBytes).toBe(trailingData.length);
  });

  it('EntropyAnalyzer calculates high entropy for pseudo-random data', async () => {
    const analyzer = new EntropyAnalyzer();

    // 1024 bytes of high-entropy random data
    const randomBytes = new Uint8Array(2048);
    for (let i = 0; i < randomBytes.length; i++) {
      randomBytes[i] = Math.floor(Math.random() * 256);
    }

    const result = await analyzer.run(randomBytes);
    expect(result.success).toBe(true);
    expect(result.data?.globalEntropy).toBeGreaterThan(7.0);
  });

  it('BinwalkAnalyzer detects and extracts embedded ZIP archive', async () => {
    const analyzer = new BinwalkAnalyzer();

    // Create a real ZIP archive using fflate
    const zipData = zipSync({
      'secret_flag.txt': new TextEncoder().encode('FLAG{embedded_zip_extracted}')
    });

    // Embed the ZIP inside dummy container bytes (at offset 100)
    const dummyHeader = new Uint8Array(100);
    dummyHeader.fill(0xAA);

    const combined = new Uint8Array(dummyHeader.length + zipData.length);
    combined.set(dummyHeader, 0);
    combined.set(zipData, dummyHeader.length);

    const result = await analyzer.run(combined);
    expect(result.success).toBe(true);
    expect(result.files.length).toBeGreaterThan(0);

    const extractedFile = result.files.find(f => f.name === 'secret_flag.txt');
    expect(extractedFile).toBeDefined();
    expect(extractedFile?.previewText).toContain('FLAG{embedded_zip_extracted}');
  });

  it('JPEG binary parser extracts COM comment markers and sampling factors', () => {
    // Construct valid minimal JPEG binary with COM marker
    const commentStr = 'c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9'; // Base64 for steghide:cEF6endvcmQ=
    const commentBytes = new TextEncoder().encode(commentStr);
    const comLength = commentBytes.length + 2;

    const jpegBytes = new Uint8Array([
      0xFF, 0xD8, // SOI
      0xFF, 0xFE, (comLength >> 8) & 0xFF, comLength & 0xFF, ...commentBytes, // COM
      0xFF, 0xC0, 0x00, 0x11, 0x08, 0x02, 0x80, 0x02, 0x80, 0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01, // SOF0 640x640 2x2,1x1,1x1
      0xFF, 0xD9  // EOI
    ]);

    const info = parseJpegStream(jpegBytes);
    expect(info.isJpeg).toBe(true);
    expect(info.comments.length).toBe(1);
    expect(info.comments[0].text).toBe(commentStr);
    expect(info.dimensions?.width).toBe(640);
    expect(info.dimensions?.height).toBe(640);
    expect(info.samplingFactorsString).toBe('2x2, 1x1, 1x1');
  });

  it('Multi-layer stego hint decoder recursively decodes Base64/Hex passwords', () => {
    // Layer 1: "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9"
    // Layer 2: "steghide:cEF6endvcmQ=" (Base64 decoded)
    // Layer 3: "steghide:pAzzword" (Base64 password decoded)
    const hint = analyzeStegoHints('JPEG Comment', 'c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9');
    expect(hint).toBeDefined();
    expect(hint?.targetTool).toBe('steghide');
    expect(hint?.candidatePassphrase).toBe('pAzzword');
    expect(hint?.decodedLayers).toContain('steghide:cEF6endvcmQ=');
    expect(hint?.confidence).toBe('high');
  });

  it('computeChannelStatistics computes exact ImageMagick metrics for RGBA', () => {
    // Create 2x2 dummy RGBA image (4 pixels)
    // Pixel 0: (10, 20, 30, 255)
    // Pixel 1: (50, 60, 70, 255)
    // Pixel 2: (100, 110, 120, 255)
    // Pixel 3: (200, 210, 220, 255)
    const rgba = new Uint8ClampedArray([
      10, 20, 30, 255,
      50, 60, 70, 255,
      100, 110, 120, 255,
      200, 210, 220, 255
    ]);

    const meta = computeChannelStatistics(rgba, 2, 2, 'JPEG');
    expect(meta.geometry).toBe('2x2');
    expect(meta.channelStatistics.red.min).toBe(10);
    expect(meta.channelStatistics.red.max).toBe(200);
    expect(meta.channelStatistics.red.mean).toBe(90);
    expect(meta.channelStatistics.blue.min).toBe(30);
    expect(meta.channelStatistics.blue.max).toBe(220);
    expect(meta.channelStatistics.blue.mean).toBe(110);
  });

  it('MetadataAnalyzer extracts decoded stego hints and publishes findings', async () => {
    const analyzer = new MetadataAnalyzer();
    const commentStr = 'c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9';
    const commentBytes = new TextEncoder().encode(commentStr);
    const comLength = commentBytes.length + 2;

    const jpegBytes = new Uint8Array([
      0xFF, 0xD8, // SOI
      0xFF, 0xFE, (comLength >> 8) & 0xFF, comLength & 0xFF, ...commentBytes, // COM
      0xFF, 0xD9  // EOI
    ]);

    const result = await analyzer.run(jpegBytes);
    expect(result.success).toBe(true);
    expect(result.data?.allComments?.length).toBe(1);
    expect(result.data?.allComments[0].text).toBe(commentStr);
    expect(result.data?.metadata['Image Properties & Geometry']['Comment']).toBe(commentStr);
    expect(result.data?.decodedStegoHints?.length).toBeGreaterThan(0);
    expect(result.data?.decodedStegoHints[0].candidatePassphrase).toBe('pAzzword');

    const stegoFinding = result.findings.find(f => f.type === 'STEGO_PASSPHRASE_HINT');
    expect(stegoFinding).toBeDefined();
    expect(stegoFinding?.description).toContain('pAzzword');
  });
});
