/**
 * The Hidden Bytes V2 - Analyzer Manager
 * High-level orchestration facade for React UI components.
 */

import { registry } from './registry';
import { defaultScheduler, TaskScheduler } from './scheduler';
import { AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor } from './types';
import { UnsupportedFormatError } from './errors';

export class AnalyzerManager {
  private scheduler: TaskScheduler;

  constructor(scheduler: TaskScheduler = defaultScheduler) {
    this.scheduler = scheduler;
  }

  public async run(
    analyzerId: string,
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const analyzer = registry.get(analyzerId);
    if (!analyzer) {
      throw new Error(`Analyzer '${analyzerId}' is not registered`);
    }

    // Check support if file descriptor is available
    if (input instanceof File) {
      const descriptor: FileDescriptor = {
        name: input.name,
        size: input.size,
        type: input.type,
        lastModified: input.lastModified
      };
      if (!analyzer.supports(descriptor)) {
        throw new UnsupportedFormatError(input.type || input.name, analyzer.name);
      }
    }

    return this.scheduler.schedule(analyzer, input, options, context);
  }

  public async runAll(
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<Map<string, AnalysisResult>> {
    let applicableAnalyzers = registry.getAll();

    if (input instanceof File) {
      const descriptor: FileDescriptor = {
        name: input.name,
        size: input.size,
        type: input.type,
        lastModified: input.lastModified
      };
      applicableAnalyzers = registry.getApplicable(descriptor);
    }

    const results = new Map<string, AnalysisResult>();
    const total = applicableAnalyzers.length;
    let completed = 0;

    const promises = applicableAnalyzers.map(async analyzer => {
      try {
        const res = await this.scheduler.schedule(analyzer, input, options, {
          ...context,
          onProgress: (p, msg) => {
            if (context.onProgress) {
              const overallProgress = Math.round(((completed + p / 100) / total) * 100);
              context.onProgress(overallProgress, `[${analyzer.name}] ${msg}`);
            }
          }
        });
        results.set(analyzer.id, res);
      } catch (err: any) {
        results.set(analyzer.id, {
          analyzerId: analyzer.id,
          analyzerName: analyzer.name,
          implementation: analyzer.type,
          version: analyzer.version,
          success: false,
          durationMs: 0,
          findings: [],
          files: [],
          warnings: [],
          error: {
            code: err.code || 'UNKNOWN_ERROR',
            message: err.message || String(err)
          }
        });
      } finally {
        completed++;
        if (context.onProgress) {
          context.onProgress(Math.round((completed / total) * 100), `Completed ${completed}/${total} analyzers`);
        }
      }
    });

    await Promise.all(promises);
    return results;
  }
}

export const analyzerManager = new AnalyzerManager();
