/**
 * The Hidden Bytes V2 - Multi-Analyzer Findings Correlator
 * Synthesizes and cross-references results across all analyzers to generate high-confidence forensic alerts.
 */

import { AnalysisResult, Finding, ExtractedFile } from './types';

export interface CorrelatedFinding {
  title: string;
  confidence: 'high' | 'medium' | 'low';
  description: string;
  sourceAnalyzers: string[];
  offset?: number;
  relatedFindings: Finding[];
}

export interface ComprehensiveReport {
  summary: {
    totalAnalyzersRun: number;
    successfulAnalyzers: number;
    totalFindings: number;
    totalExtractedFiles: number;
    criticalAlertsCount: number;
    executionTimeMs: number;
  };
  correlatedFindings: CorrelatedFinding[];
  allExtractedFiles: ExtractedFile[];
  resultsByAnalyzer: Record<string, AnalysisResult>;
}

export class FindingsCorrelator {
  public static correlate(results: Map<string, AnalysisResult>): ComprehensiveReport {
    const resultsObj: Record<string, AnalysisResult> = {};
    const allFindings: Finding[] = [];
    const allFiles: ExtractedFile[] = [];
    const fileHashes = new Set<string>();
    let totalTime = 0;
    let successfulCount = 0;

    for (const [id, res] of results.entries()) {
      resultsObj[id] = res;
      totalTime += res.durationMs || 0;
      if (res.success) successfulCount++;

      allFindings.push(...res.findings);

      for (const file of res.files) {
        const hashKey = file.sha256 || file.path;
        if (!fileHashes.has(hashKey)) {
          fileHashes.add(hashKey);
          allFiles.push(file);
        }
      }
    }

    const correlated: CorrelatedFinding[] = [];

    // 1. Cross-reference: Steganography Passphrase Hints in Comments/Metadata
    const metaRes = results.get('metadata');
    if (metaRes) {
      const stegoHints = metaRes.findings.filter(f => f.type === 'STEGO_PASSPHRASE_HINT');
      for (const hint of stegoHints) {
        correlated.push({
          title: 'Stego Passphrase / Credential Uncovered',
          confidence: 'high',
          description: hint.description,
          sourceAnalyzers: ['metadata', 'steghide'],
          relatedFindings: [hint]
        });
      }
    }

    // 2. Cross-reference: Trailing Overlay / Embedded Archive + High Entropy + Strings
    const binwalkRes = results.get('binwalk');
    const entropyRes = results.get('entropy');
    const stringsRes = results.get('strings');
    const sigRes = results.get('signatures');

    if (binwalkRes && entropyRes) {
      const embeddedSigs = binwalkRes.findings.filter(f => f.type.startsWith('BINWALK_') && f.offset && f.offset > 0);
      const highEntropyBlocks = entropyRes.findings.filter(f => f.type === 'HIGH_ENTROPY_BLOCK');

      for (const sig of embeddedSigs) {
        const matchingEntropy = highEntropyBlocks.find(e => e.offset !== undefined && Math.abs(e.offset - (sig.offset || 0)) < 4096);
        if (matchingEntropy) {
          correlated.push({
            title: 'High-Confidence Embedded Payload',
            confidence: 'high',
            description: `Correlated ${sig.description} at offset 0x${(sig.offset || 0).toString(16)} with high-entropy density region, confirming non-standard embedded archive/payload.`,
            sourceAnalyzers: ['binwalk', 'entropy'],
            offset: sig.offset,
            relatedFindings: [sig, matchingEntropy]
          });
        }
      }
    }

    // 3. Cross-reference: Trailing Overlay from Signatures with Strings in the overlay region
    if (sigRes && stringsRes) {
      const overlayFinding = sigRes.findings.find(f => f.type === 'TRAILING_OVERLAY');
      if (overlayFinding && overlayFinding.offset !== undefined) {
        const overlayOffset = overlayFinding.offset;
        const stringsInOverlay = stringsRes.findings.filter(f => f.offset !== undefined && f.offset >= overlayOffset);

        if (stringsInOverlay.length > 0) {
          correlated.push({
            title: 'Text In Appended Steganographic Overlay',
            confidence: 'high',
            description: `Detected readable text/patterns inside the trailing data appended after the file container marker (offset 0x${overlayOffset.toString(16)}).`,
            sourceAnalyzers: ['signatures', 'strings'],
            offset: overlayOffset,
            relatedFindings: [overlayFinding, ...stringsInOverlay]
          });
        }
      }
    }

    // 4. Flags and Credentials detected
    const flagFindings = allFindings.filter(f => f.type === 'FLAG_DETECTED' || f.severity === 'critical');
    for (const flag of flagFindings) {
      correlated.push({
        title: 'CTF Flag / Key Uncovered',
        confidence: 'high',
        description: flag.description,
        sourceAnalyzers: ['strings'],
        offset: flag.offset,
        relatedFindings: [flag]
      });
    }

    const criticalCount = allFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length;

    return {
      summary: {
        totalAnalyzersRun: results.size,
        successfulAnalyzers: successfulCount,
        totalFindings: allFindings.length,
        totalExtractedFiles: allFiles.length,
        criticalAlertsCount: criticalCount,
        executionTimeMs: totalTime
      },
      correlatedFindings: correlated,
      allExtractedFiles: allFiles,
      resultsByAnalyzer: resultsObj
    };
  }
}
