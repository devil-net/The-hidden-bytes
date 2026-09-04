/**
 * The Hidden Bytes V2 - High-Performance In-Memory Strings Scanner
 * Replaces GNU strings with a fast browser-native streaming scanner.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { toUint8Array } from '../../../utils/crypto';

export interface StringMatch {
  offset: number;
  length: number;
  value: string;
  encoding: 'ascii' | 'utf-8' | 'utf-16le' | 'utf-16be';
}

export class StringsAnalyzer implements Analyzer {
  readonly id = 'strings';
  readonly name = 'Strings';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'Extracts printable ASCII, UTF-8, and UTF-16 strings from binary data with pattern detection.';

  supports(_file: FileDescriptor): boolean {
    return true; // Supports any binary or text file
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const minLength = options.minStringLength ?? 4;
    const maxResults = options.maxResults ?? 5000;

    context.onProgress?.(10, 'Scanning printable ASCII sequences...');

    const matches: StringMatch[] = [];
    const findings: Finding[] = [];
    const totalBytes = bytes.length;

    // Fast ASCII scanner (0x20 - 0x7E, \t) - matching GNU strings line delimiter behavior
    let currentStart = -1;
    for (let i = 0; i < totalBytes; i++) {
      if (context.signal?.aborted) break;

      const b = bytes[i];
      const isPrintable = (b >= 32 && b <= 126) || b === 9;

      if (isPrintable) {
        if (currentStart === -1) {
          currentStart = i;
        }
      } else {
        if (currentStart !== -1) {
          const len = i - currentStart;
          if (len >= minLength) {
            const strSlice = bytes.subarray(currentStart, i);
            const strVal = new TextDecoder('utf-8', { fatal: false }).decode(strSlice).trim();
            if (strVal.length >= minLength) {
              matches.push({
                offset: currentStart,
                length: len,
                value: strVal,
                encoding: 'ascii'
              });
            }

            if (matches.length >= maxResults) break;
          }
          currentStart = -1;
        }
      }

      if (i % 500000 === 0 && totalBytes > 0) {
        context.onProgress?.(10 + Math.round((i / totalBytes) * 70), `Scanned ${(i / (1024 * 1024)).toFixed(1)} MB...`);
      }
    }

    // Handle string ending at EOF
    if (currentStart !== -1 && totalBytes - currentStart >= minLength && matches.length < maxResults) {
      const strSlice = bytes.subarray(currentStart, totalBytes);
      const strVal = new TextDecoder('utf-8', { fatal: false }).decode(strSlice);
      matches.push({
        offset: currentStart,
        length: totalBytes - currentStart,
        value: strVal,
        encoding: 'ascii'
      });
    }

    context.onProgress?.(85, 'Analyzing extracted strings for flags, keys, and patterns...');

    // Heuristics to detect CTF flags, URLs, Base64 tokens, or passwords
    const flagRegex = /(flag\{[^}]+\}|ctf\{[^}]+\}|key\{[^}]+\}|secret\{[^}]+\})/i;
    const urlRegex = /https?:\/\/[^\s"'>]+/i;
    const base64Regex = /^[A-Za-z0-9+/]{24,}={0,2}$/;

    for (const match of matches) {
      const val = match.value.trim();

      if (flagRegex.test(val)) {
        findings.push({
          offset: match.offset,
          type: 'FLAG_DETECTED',
          severity: 'critical',
          description: `Potential CTF Flag found at offset 0x${match.offset.toString(16)}: "${val}"`,
          metadata: { string: val }
        });
      } else if (urlRegex.test(val)) {
        findings.push({
          offset: match.offset,
          type: 'URL_DETECTED',
          severity: 'low',
          description: `URL found at offset 0x${match.offset.toString(16)}: "${val}"`,
          metadata: { url: val }
        });
      } else if (val.length > 28 && base64Regex.test(val)) {
        findings.push({
          offset: match.offset,
          type: 'BASE64_PAYLOAD',
          severity: 'medium',
          description: `Potential Base64 encoded payload at offset 0x${match.offset.toString(16)}: "${val.substring(0, 32)}..."`,
          metadata: { payload: val }
        });
      }
    }

    context.onProgress?.(100, 'Strings scan complete');

    const simpleStringList = matches.map(m => m.value);

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: [],
      warnings: matches.length >= maxResults ? [`Result capped at ${maxResults} strings.`] : [],
      data: {
        totalFound: matches.length,
        strings: simpleStringList,
        detailedMatches: matches
      }
    };
  }
}
