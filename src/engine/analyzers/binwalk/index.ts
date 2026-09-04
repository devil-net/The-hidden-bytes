/**
 * The Hidden Bytes V2 - In-Browser Binwalk & Embedded Stream Carving Engine
 * Deep scans signatures, parses container boundaries, decompresses streams (zlib/gzip/zip),
 * and safely extracts embedded files directly into browser RAM.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding, ExtractedFile } from '../../types';
import { toUint8Array, calculateSha256 } from '../../../utils/crypto';
import { SIGNATURES, MagicSignature } from '../signatures/database';
import { unzipSync, inflateSync, gunzipSync } from 'fflate';

export class BinwalkAnalyzer implements Analyzer {
  readonly id = 'binwalk';
  readonly name = 'Binwalk';
  readonly version = '3.0.0-browser-wasm';
  readonly type = 'wasm' as const;
  readonly description = 'Firmware analysis and embedded file extraction engine running entirely in browser RAM.';

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
    const shouldExtract = options.extractFiles !== false; // Default true
    const maxFiles = options.maxFiles ?? 100;
    const maxBytes = options.maxExtractedBytes ?? 50 * 1024 * 1024; // 50MB safety limit

    context.onProgress?.(10, 'Scanning signatures for Binwalk analysis...');

    const findings: Finding[] = [];
    const extractedFiles: ExtractedFile[] = [];
    const stdoutLines: string[] = [
      'DECIMAL       HEXADECIMAL     DESCRIPTION',
      '--------------------------------------------------------------------------------'
    ];

    let extractedBytesCount = 0;

    // Scan for all signature matches
    const signatureMatches: Array<{ offset: number; sig: MagicSignature }> = [];
    for (let i = 0; i < totalBytes - 4; i++) {
      if (context.signal?.aborted) break;

      for (const sig of SIGNATURES) {
        if (this.matchesAt(bytes, i, sig.magic)) {
          // Avoid 2-byte false positives in random data
          if (sig.magic.length <= 2 && i > 0) continue;

          signatureMatches.push({ offset: i, sig });
          const hex = `0x${i.toString(16).toUpperCase()}`;
          const decPad = i.toString().padEnd(14, ' ');
          const hexPad = hex.padEnd(16, ' ');
          stdoutLines.push(`${decPad}${hexPad}${sig.description}`);

          findings.push({
            offset: i,
            type: `BINWALK_${sig.category.toUpperCase()}`,
            severity: i === 0 ? 'info' : 'high',
            description: `${sig.description} at offset ${hex} (${i} bytes)`,
            metadata: {
              category: sig.category,
              extension: sig.extension
            }
          });
          break;
        }
      }
    }

    // Extraction pass
    if (shouldExtract && signatureMatches.length > 0) {
      context.onProgress?.(50, 'Extracting embedded file streams...');

      for (let idx = 0; idx < signatureMatches.length; idx++) {
        if (extractedFiles.length >= maxFiles || extractedBytesCount >= maxBytes) break;

        const current = signatureMatches[idx];
        const next = signatureMatches[idx + 1];
        const startOffset = current.offset;

        // Determine slice length
        let endOffset = next ? next.offset : totalBytes;

        // For ZIP archives: parse actual ZIP directory structure
        if (current.sig.extension === 'zip') {
          try {
            const zipSlice = bytes.subarray(startOffset);
            const unzipped = unzipSync(zipSlice);

            for (const [filename, fileData] of Object.entries(unzipped)) {
              if (extractedFiles.length >= maxFiles || extractedBytesCount + fileData.length > maxBytes) break;

              const isText = this.checkIsText(fileData);
              const previewText = isText ? new TextDecoder('utf-8').decode(fileData.subarray(0, 500)) : undefined;
              const sha256 = await calculateSha256(fileData);

              extractedFiles.push({
                name: filename.split('/').pop() || filename,
                path: `extracted_zip_${startOffset}/${filename}`,
                size: fileData.length,
                mimeType: 'application/octet-stream',
                data: fileData,
                sha256,
                previewText,
                isText
              });

              extractedBytesCount += fileData.length;
            }
            continue;
          } catch {
            // Raw carving fallback if zip parser fails
          }
        }

        // For GZIP compressed streams: try inflating
        if (current.sig.extension === 'gz') {
          try {
            const gzSlice = bytes.subarray(startOffset);
            const decompressed = gunzipSync(gzSlice);
            const sha256 = await calculateSha256(decompressed);
            const isText = this.checkIsText(decompressed);

            extractedFiles.push({
              name: `decompressed_0x${startOffset.toString(16)}.bin`,
              path: `extracted/decompressed_0x${startOffset.toString(16)}.bin`,
              size: decompressed.length,
              mimeType: 'application/octet-stream',
              data: decompressed,
              sha256,
              previewText: isText ? new TextDecoder('utf-8').decode(decompressed.subarray(0, 500)) : undefined,
              isText
            });

            extractedBytesCount += decompressed.length;
            continue;
          } catch {
            // Fallback to carving
          }
        }

        // For ZLIB raw streams: try inflating
        if (current.sig.extension === 'zlib') {
          try {
            const zlibSlice = bytes.subarray(startOffset);
            const decompressed = inflateSync(zlibSlice);
            const sha256 = await calculateSha256(decompressed);
            const isText = this.checkIsText(decompressed);

            extractedFiles.push({
              name: `zlib_0x${startOffset.toString(16)}.bin`,
              path: `extracted/zlib_0x${startOffset.toString(16)}.bin`,
              size: decompressed.length,
              mimeType: 'application/octet-stream',
              data: decompressed,
              sha256,
              previewText: isText ? new TextDecoder('utf-8').decode(decompressed.subarray(0, 500)) : undefined,
              isText
            });

            extractedBytesCount += decompressed.length;
            continue;
          } catch {
            // Fallback
          }
        }

        // Standard embedded stream carving for non-archive or embedded image headers
        if (startOffset > 0) { // Don't carve the container itself if at offset 0
          const carvedSlice = bytes.subarray(startOffset, endOffset);
          const filename = `embedded_0x${startOffset.toString(16)}.${current.sig.extension}`;
          const sha256 = await calculateSha256(carvedSlice);
          const isText = this.checkIsText(carvedSlice);

          extractedFiles.push({
            name: filename,
            path: `extracted/${filename}`,
            size: carvedSlice.length,
            mimeType: current.sig.mimeType,
            data: carvedSlice,
            sha256,
            previewText: isText ? new TextDecoder('utf-8').decode(carvedSlice.subarray(0, 500)) : undefined,
            isText
          });

          extractedBytesCount += carvedSlice.length;
        }
      }
    }

    context.onProgress?.(100, 'Binwalk analysis complete');

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: extractedFiles,
      stdout: stdoutLines.join('\n'),
      warnings: extractedFiles.length >= maxFiles ? [`Extraction reached maximum file limit (${maxFiles} files)`] : [],
      data: {
        totalSignaturesFound: signatureMatches.length,
        totalFilesExtracted: extractedFiles.length
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

  private checkIsText(data: Uint8Array): boolean {
    const sampleSize = Math.min(data.length, 512);
    let printable = 0;
    for (let i = 0; i < sampleSize; i++) {
      const b = data[i];
      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) printable++;
    }
    return sampleSize > 0 && printable / sampleSize > 0.85;
  }
}
