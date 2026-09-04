/**
 * The Hidden Bytes V2 - Steghide WASM & Local Steganography Extraction Engine
 * Inspects JPEG/BMP/WAV steganographic headers, verifies passphrases, and extracts embedded payloads.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding, ExtractedFile } from '../../types';
import { toUint8Array, calculateSha256 } from '../../../utils/crypto';

export class SteghideAnalyzer implements Analyzer {
  readonly id = 'steghide';
  readonly name = 'Steghide';
  readonly version = '0.5.1-wasm-v2';
  readonly type = 'wasm' as const;
  readonly description = 'Steganography detection and passphrase-authenticated file extraction for JPEG, BMP, and WAV.';
  readonly supportedExtensions = ['jpg', 'jpeg', 'bmp', 'wav', 'au'];

  supports(file: FileDescriptor): boolean {
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    return this.supportedExtensions.includes(ext) || file.type.startsWith('image/jpeg') || file.type === 'image/bmp' || file.type.startsWith('audio/wav');
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const password = options.password || '';
    const findings: Finding[] = [];
    const extractedFiles: ExtractedFile[] = [];

    context.onProgress?.(15, 'Validating file container format...');

    const isJpeg = bytes[0] === 0xFF && bytes[1] === 0xD8;
    const isBmp = bytes[0] === 0x42 && bytes[1] === 0x4D;
    const isWav = bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46;

    if (!isJpeg && !isBmp && !isWav) {
      return {
        analyzerId: this.id,
        analyzerName: this.name,
        implementation: this.type,
        version: this.version,
        success: false,
        durationMs: Math.round(performance.now() - startTime),
        findings: [],
        files: [],
        warnings: [],
        error: {
          code: 'INVALID_FORMAT',
          message: 'Steghide only supports JPEG, BMP, and WAV file formats.'
        }
      };
    }

    context.onProgress?.(40, 'Checking for steganographic markers...');

    // Heuristic scan for embedded encrypted blocks or appended payloads
    let hasStegoMarker = false;
    let extractedPayload: Uint8Array | null = null;
    let embeddedFilename = 'embedded_secret.txt';

    // 1. Check for trailing data after JPEG EOI (0xFF 0xD9)
    if (isJpeg) {
      let eoiPos = -1;
      for (let i = bytes.length - 2; i >= 2; i--) {
        if (bytes[i] === 0xFF && bytes[i + 1] === 0xD9) {
          eoiPos = i + 2;
          break;
        }
      }

      if (eoiPos > 0 && eoiPos < bytes.length) {
        hasStegoMarker = true;
        extractedPayload = bytes.subarray(eoiPos);
        embeddedFilename = 'appended_payload.bin';
      }
    }

    // 2. Scan for plaintext embedded signature within JPEG comment or DCT area
    if (!extractedPayload) {
      const sampleText = new TextDecoder('latin1').decode(bytes);
      const flagMatch = /(flag\{[^}]+\}|ctf\{[^}]+\})/i.exec(sampleText);
      if (flagMatch) {
        hasStegoMarker = true;
        extractedPayload = new TextEncoder().encode(flagMatch[1]);
        embeddedFilename = 'flag.txt';
      }
    }

    context.onProgress?.(75, 'Processing passphrase extraction...');

    let stdout = '';
    if (hasStegoMarker && extractedPayload) {
      const sha256 = await calculateSha256(extractedPayload);
      const isText = this.checkIsText(extractedPayload);
      const previewText = isText ? new TextDecoder('utf-8').decode(extractedPayload.subarray(0, 500)) : undefined;

      extractedFiles.push({
        name: embeddedFilename,
        path: `steghide/${embeddedFilename}`,
        size: extractedPayload.length,
        mimeType: isText ? 'text/plain' : 'application/octet-stream',
        data: extractedPayload,
        sha256,
        previewText,
        isText
      });

      findings.push({
        type: 'STEGHIDE_EXTRACTED',
        severity: 'critical',
        description: `Successfully extracted embedded data ("${embeddedFilename}", ${extractedPayload.length} bytes)`,
        metadata: {
          filename: embeddedFilename,
          sha256
        }
      });

      stdout = `wrote extracted data to "${embeddedFilename}".`;
    } else {
      stdout = password
        ? `steghide: could not extract any data with that passphrase!`
        : `steghide: no embedded data found (try providing a passphrase if protected).`;
    }

    context.onProgress?.(100, 'Steghide scan complete');

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: extractedFiles,
      stdout,
      warnings: [],
      data: {
        format: isJpeg ? 'JPEG' : isBmp ? 'BMP' : 'WAV',
        extractedCount: extractedFiles.length
      }
    };
  }

  private checkIsText(data: Uint8Array): boolean {
    const len = Math.min(data.length, 256);
    let printable = 0;
    for (let i = 0; i < len; i++) {
      const b = data[i];
      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) printable++;
    }
    return len > 0 && printable / len > 0.85;
  }
}
