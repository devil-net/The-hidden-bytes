/**
 * The Hidden Bytes V2 - Shannon Entropy & Anomaly Analyzer
 * Analyzes randomness across binary blocks to detect encrypted/compressed stego regions.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { toUint8Array } from '../../../utils/crypto';

export interface EntropyBlock {
  offset: number;
  hexOffset: string;
  entropy: number;
}

export class EntropyAnalyzer implements Analyzer {
  readonly id = 'entropy';
  readonly name = 'Entropy';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'Calculates Shannon entropy across block chunks to map compressed, encrypted, and stego data.';

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

    // Determine adaptive block size (between 256 and 4096 bytes)
    const targetBlocks = options.targetBlocks ?? 100;
    const blockSize = Math.max(256, Math.min(4096, Math.floor(totalBytes / targetBlocks) || 256));

    context.onProgress?.(10, `Calculating Shannon entropy (block size: ${blockSize} bytes)...`);

    const blocks: EntropyBlock[] = [];
    const findings: Finding[] = [];
    let highEntropyRunStart = -1;
    let highEntropyRunLength = 0;
    let overallFrequency = new Array(256).fill(0);

    for (let offset = 0; offset < totalBytes; offset += blockSize) {
      if (context.signal?.aborted) break;

      const currentBlockSize = Math.min(blockSize, totalBytes - offset);
      const freq = new Array(256).fill(0);

      for (let i = 0; i < currentBlockSize; i++) {
        const b = bytes[offset + i];
        freq[b]++;
        overallFrequency[b]++;
      }

      // Shannon entropy H = -sum(p * log2(p))
      let entropy = 0;
      for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
          const p = freq[i] / currentBlockSize;
          entropy -= p * Math.log2(p);
        }
      }

      blocks.push({
        offset,
        hexOffset: `0x${offset.toString(16).toUpperCase()}`,
        entropy: Math.round(entropy * 1000) / 1000
      });

      // High entropy detection (> 7.5 indicates dense compression or encryption)
      if (entropy >= 7.5) {
        if (highEntropyRunStart === -1) {
          highEntropyRunStart = offset;
          highEntropyRunLength = currentBlockSize;
        } else {
          highEntropyRunLength += currentBlockSize;
        }
      } else {
        if (highEntropyRunStart !== -1 && highEntropyRunLength >= blockSize * 2) {
          findings.push({
            offset: highEntropyRunStart,
            length: highEntropyRunLength,
            type: 'HIGH_ENTROPY_BLOCK',
            severity: 'medium',
            description: `High entropy region (entropy >= 7.5) spanning ${highEntropyRunLength.toLocaleString()} bytes at offset 0x${highEntropyRunStart.toString(16).toUpperCase()} (likely encrypted or compressed payload).`
          });
          highEntropyRunStart = -1;
          highEntropyRunLength = 0;
        } else {
          highEntropyRunStart = -1;
          highEntropyRunLength = 0;
        }
      }

      if (offset % (blockSize * 50) === 0) {
        context.onProgress?.(10 + Math.round((offset / totalBytes) * 80), `Processed ${(offset / (1024 * 1024)).toFixed(1)} MB...`);
      }
    }

    if (highEntropyRunStart !== -1 && highEntropyRunLength >= blockSize * 2) {
      findings.push({
        offset: highEntropyRunStart,
        length: highEntropyRunLength,
        type: 'HIGH_ENTROPY_BLOCK',
        severity: 'medium',
        description: `High entropy region spanning ${highEntropyRunLength.toLocaleString()} bytes at offset 0x${highEntropyRunStart.toString(16).toUpperCase()}.`
      });
    }

    // Global file entropy
    let globalEntropy = 0;
    for (let i = 0; i < 256; i++) {
      if (overallFrequency[i] > 0) {
        const p = overallFrequency[i] / totalBytes;
        globalEntropy -= p * Math.log2(p);
      }
    }

    context.onProgress?.(100, 'Entropy calculation complete');

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
        globalEntropy: Math.round(globalEntropy * 1000) / 1000,
        blockSize,
        totalBlocks: blocks.length,
        blocks
      }
    };
  }
}
