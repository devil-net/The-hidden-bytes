/**
 * The Hidden Bytes V2 - Zsteg Steganography Compatible Engine
 * Detects hidden data, text payloads, and embedded files in PNG/BMP color channels & bit planes.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding, ExtractedFile } from '../../types';
import { toUint8Array, calculateSha256 } from '../../../utils/crypto';
import { SIGNATURES } from '../signatures/database';
import { inflateSync } from 'fflate';

interface ChannelConfig {
  name: string;
  bitPlane: number;
  channels: ('r' | 'g' | 'b' | 'a')[];
  order: 'xy' | 'yx';
  bitOrder: 'lsb' | 'msb';
}

export class ZstegAnalyzer implements Analyzer {
  readonly id = 'zsteg';
  readonly name = 'Zsteg';
  readonly version = '2.0.0-browser-compatible';
  readonly type = 'compatible' as const;
  readonly description = 'Detects hidden data, LSB payloads, and compressed streams in PNG and BMP image channels.';
  readonly supportedExtensions = ['png', 'bmp'];

  supports(file: FileDescriptor): boolean {
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    return ext === 'png' || ext === 'bmp' || file.type === 'image/png' || file.type === 'image/bmp';
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    _options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const blob = new Blob([bytes.buffer as ArrayBuffer]);

    context.onProgress?.(10, 'Decoding PNG pixel buffers...');

    const imgBitmap = await createImageBitmap(blob);
    const width = imgBitmap.width;
    const height = imgBitmap.height;

    const canvas = new OffscreenCanvas(width, height);
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('Could not get 2D context for Zsteg');

    ctx.drawImage(imgBitmap, 0, 0);
    const imgData = ctx.getImageData(0, 0, width, height);
    const pixels = imgData.data;

    const findings: Finding[] = [];
    const extractedFiles: ExtractedFile[] = [];
    const stdoutLines: string[] = [];

    const testConfigs: ChannelConfig[] = [
      { name: 'b1,r,lsb,xy', bitPlane: 1, channels: ['r'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,g,lsb,xy', bitPlane: 1, channels: ['g'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,b,lsb,xy', bitPlane: 1, channels: ['b'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,rgb,lsb,xy', bitPlane: 1, channels: ['r', 'g', 'b'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,bgr,lsb,xy', bitPlane: 1, channels: ['b', 'g', 'r'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,rgba,lsb,xy', bitPlane: 1, channels: ['r', 'g', 'b', 'a'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b1,abgr,lsb,xy', bitPlane: 1, channels: ['a', 'b', 'g', 'r'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b2,r,lsb,xy', bitPlane: 2, channels: ['r'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b2,g,lsb,xy', bitPlane: 2, channels: ['g'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b2,b,lsb,xy', bitPlane: 2, channels: ['b'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b2,rgb,lsb,xy', bitPlane: 2, channels: ['r', 'g', 'b'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b4,r,lsb,xy', bitPlane: 4, channels: ['r'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b4,g,lsb,xy', bitPlane: 4, channels: ['g'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b4,b,lsb,xy', bitPlane: 4, channels: ['b'], order: 'xy', bitOrder: 'lsb' },
      { name: 'b4,rgb,lsb,xy', bitPlane: 4, channels: ['r', 'g', 'b'], order: 'xy', bitOrder: 'lsb' }
    ];

    const totalTests = testConfigs.length;

    for (let t = 0; t < totalTests; t++) {
      if (context.signal?.aborted) break;

      const cfg = testConfigs[t];
      context.onProgress?.(
        20 + Math.round((t / totalTests) * 70),
        `Testing ${cfg.name}...`
      );

      const extractedBytes = this.extractChannelBits(pixels, width, height, cfg, 65536);
      const result = await this.analyzeExtractedBitstream(extractedBytes, cfg.name);

      if (result) {
        stdoutLines.push(`[+] ${cfg.name.padEnd(20)} .. ${result.label}`);

        findings.push({
          type: 'ZSTEG_PAYLOAD',
          severity: result.isFlag ? 'critical' : 'high',
          description: `[${cfg.name}] ${result.label}`,
          metadata: {
            channel: cfg.name,
            details: result.label
          }
        });

        if (result.extractedFile) {
          extractedFiles.push(result.extractedFile);
        }
      }
    }

    context.onProgress?.(100, 'Zsteg analysis complete');

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: extractedFiles,
      stdout: stdoutLines.length > 0 ? stdoutLines.join('\n') : 'No obvious steganographic payloads detected in tested channel permutations.',
      warnings: [],
      data: {
        dimensions: { width, height },
        permutationsTested: totalTests,
        payloadsFound: findings.length
      }
    };
  }

  private extractChannelBits(
    pixels: Uint8ClampedArray,
    width: number,
    height: number,
    cfg: ChannelConfig,
    maxOutputBytes: number
  ): Uint8Array {
    const output = new Uint8Array(maxOutputBytes);
    let byteAcc = 0;
    let bitCount = 0;
    let outIdx = 0;

    const channelIndices = cfg.channels.map(c => {
      switch (c) {
        case 'r': return 0;
        case 'g': return 1;
        case 'b': return 2;
        case 'a': return 3;
      }
    });

    const mask = (1 << cfg.bitPlane) - 1;

    for (let y = 0; y < height; y++) {
      for (let x = 0; x < width; x++) {
        const pixelIdx = (y * width + x) * 4;

        for (const ch of channelIndices) {
          const val = pixels[pixelIdx + ch];
          const bits = val & mask;

          for (let b = 0; b < cfg.bitPlane; b++) {
            const bit = (bits >> b) & 1;
            byteAcc = (byteAcc << 1) | bit;
            bitCount++;

            if (bitCount === 8) {
              output[outIdx++] = byteAcc;
              byteAcc = 0;
              bitCount = 0;
              if (outIdx >= maxOutputBytes) return output;
            }
          }
        }
      }
    }

    return output.subarray(0, outIdx);
  }

  private async analyzeExtractedBitstream(
    bytes: Uint8Array,
    channelName: string
  ): Promise<{ label: string; isFlag?: boolean; extractedFile?: ExtractedFile } | null> {
    if (bytes.length < 8) return null;

    for (const sig of SIGNATURES) {
      if (this.matchesHeader(bytes, sig.magic)) {
        const filename = `zsteg_${channelName.replace(/,/g, '_')}.${sig.extension}`;
        const sha256 = await calculateSha256(bytes);
        return {
          label: `file: ${sig.description} (size: ${bytes.length} bytes)`,
          extractedFile: {
            name: filename,
            path: `zsteg/${filename}`,
            size: bytes.length,
            mimeType: sig.mimeType,
            data: bytes,
            sha256,
            isText: false
          }
        };
      }
    }

    if (bytes[0] === 0x78 && (bytes[1] === 0x9C || bytes[1] === 0xDA || bytes[1] === 0x01)) {
      try {
        const inflated = inflateSync(bytes);
        const isText = this.isPrintableText(inflated, 64);
        const textSample = isText ? new TextDecoder('utf-8').decode(inflated.subarray(0, 100)) : 'binary payload';
        const sha256 = await calculateSha256(inflated);

        return {
          label: `zlib stream: "${textSample.trim()}" (inflated: ${inflated.length} bytes)`,
          extractedFile: {
            name: `zsteg_inflated_${channelName.replace(/,/g, '_')}.bin`,
            path: `zsteg/inflated_${channelName.replace(/,/g, '_')}.bin`,
            size: inflated.length,
            mimeType: 'application/octet-stream',
            data: inflated,
            sha256,
            previewText: isText ? textSample : undefined,
            isText
          }
        };
      } catch {
        // Not zlib
      }
    }

    const sampleLen = Math.min(bytes.length, 256);
    let printable = 0;
    for (let i = 0; i < sampleLen; i++) {
      const b = bytes[i];
      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
        printable++;
      }
    }

    if (printable / sampleLen > 0.88) {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 200));
      const isFlag = /flag\{|ctf\{|key\{/i.test(text);
      const clean = text.replace(/[\r\n\t]+/g, ' ').trim();
      if (clean.length > 5) {
        return {
          label: `text: "${clean.substring(0, 80)}"`,
          isFlag
        };
      }
    }

    return null;
  }

  private matchesHeader(bytes: Uint8Array, pattern: number[]): boolean {
    if (pattern.length > bytes.length) return false;
    for (let i = 0; i < pattern.length; i++) {
      if (bytes[i] !== pattern[i]) return false;
    }
    return true;
  }

  private isPrintableText(data: Uint8Array, checkLen: number): boolean {
    const len = Math.min(data.length, checkLen);
    let count = 0;
    for (let i = 0; i < len; i++) {
      const b = data[i];
      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) count++;
    }
    return len > 0 && count / len > 0.85;
  }
}
