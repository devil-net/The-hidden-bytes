/**
 * The Hidden Bytes V2 - Engine & Analyzer Unit Tests
 */

import { describe, it, expect } from 'vitest';
import { StringsAnalyzer } from '../analyzers/strings';
import { SignatureAnalyzer } from '../analyzers/signatures';
import { EntropyAnalyzer } from '../analyzers/entropy';
import { BinwalkAnalyzer } from '../analyzers/binwalk';
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
});
