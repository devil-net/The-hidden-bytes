/**
 * The Hidden Bytes V2 - Magic Signature & Embedded Header Scanner
 * Detects file containers, embedded payloads, and trailing overlays in browser RAM.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { SIGNATURES, MagicSignature } from './database';
import { toUint8Array } from '../../../utils/crypto';

export interface SignatureMatch {
  offset: number;
  hexOffset: string;
  signature: MagicSignature;
  description: string;
}

export class SignatureAnalyzer implements Analyzer {
  readonly id = 'signatures';
  readonly name = 'Signature Scanner';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'Deep scans binary streams for magic headers, embedded files, and trailing overlays.';

  supports(_file: FileDescriptor): boolean {
    return true;
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const totalBytes = bytes.length;
    const matches: SignatureMatch[] = [];
    const findings: Finding[] = [];

    context.onProgress?.(10, 'Scanning file headers...');

    // 1. Identify primary container header at offset 0
    let primarySig: MagicSignature | null = null;
    for (const sig of SIGNATURES) {
      if (this.matchesAt(bytes, 0, sig.magic)) {
        primarySig = sig;
        matches.push({
          offset: 0,
          hexOffset: '0x0',
          signature: sig,
          description: sig.description
        });
        findings.push({
          offset: 0,
          type: 'PRIMARY_CONTAINER',
          severity: 'info',
          description: `Primary file container identified as: ${sig.description}`
        });
        break;
      }
    }

    context.onProgress?.(30, 'Deep scanning embedded signatures...');

    // 2. Deep scan for embedded signatures inside the stream
    const step = options.fastScan ? 4 : 1;
    for (let i = 1; i < totalBytes - 4; i += step) {
      if (context.signal?.aborted) break;

      for (const sig of SIGNATURES) {
        if (this.matchesAt(bytes, i, sig.magic)) {
          // Verify it's not a trivial false positive (e.g. short 2-byte magic in noisy stream)
          if (sig.magic.length <= 2 && !options.deepScanAll) {
            continue;
          }

          matches.push({
            offset: i,
            hexOffset: `0x${i.toString(16).toUpperCase()}`,
            signature: sig,
            description: sig.description
          });

          findings.push({
            offset: i,
            type: 'EMBEDDED_FILE',
            severity: 'high',
            description: `Embedded ${sig.description} found at offset 0x${i.toString(16).toUpperCase()} (${i} bytes)`,
            metadata: {
              category: sig.category,
              extension: sig.extension,
              mimeType: sig.mimeType
            }
          });
          break;
        }
      }

      if (i % 250000 === 0 && totalBytes > 0) {
        context.onProgress?.(30 + Math.round((i / totalBytes) * 50), `Deep scan ${(i / (1024 * 1024)).toFixed(1)} MB...`);
      }
    }

    context.onProgress?.(85, 'Analyzing trailing overlays...');

    // 3. Trailing overlay detection (steganographic appended bytes)
    if (primarySig && primarySig.trailer) {
      const trailer = primarySig.trailer;
      let lastTrailerPos = -1;

      for (let i = totalBytes - trailer.length; i >= 0; i--) {
        if (this.matchesAt(bytes, i, trailer)) {
          lastTrailerPos = i + trailer.length;
          break;
        }
      }

      if (lastTrailerPos > 0 && lastTrailerPos < totalBytes) {
        const overlaySize = totalBytes - lastTrailerPos;
        findings.push({
          offset: lastTrailerPos,
          length: overlaySize,
          type: 'TRAILING_OVERLAY',
          severity: 'critical',
          description: `Steganographic appended overlay detected! Found ${overlaySize.toLocaleString()} bytes appended after end of ${primarySig.name} container.`,
          metadata: {
            overlayOffset: lastTrailerPos,
            overlayBytes: overlaySize
          }
        });
      }
    }

    context.onProgress?.(100, 'Signature scan complete');

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: [],
      warnings: [],
      data: {
        totalMatches: matches.length,
        primaryContainer: primarySig ? primarySig.name : 'Unknown',
        matches
      }
    };
  }

  private matchesAt(bytes: Uint8Array, offset: number, pattern: number[]): boolean {
    if (offset + pattern.length > bytes.length) return false;
    for (let j = 0; j < pattern.length; j++) {
      if (bytes[offset + j] !== pattern[j]) return false;
    }
    return true;
  }
}
