/**
 * The Hidden Bytes V2 - Task Scheduler & Concurrency Pool
 * Orchestrates analyzer execution and controls concurrent worker workloads.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext } from './types';
import { AbortedError } from './errors';

export interface QueuedTask {
  id: string;
  analyzer: Analyzer;
  input: File | Blob | Uint8Array | ArrayBuffer;
  options: AnalyzerOptions;
  context: AnalyzerContext;
  resolve: (result: AnalysisResult) => void;
  reject: (error: any) => void;
}

export class TaskScheduler {
  private maxConcurrency: number;
  private runningCount: number = 0;
  private queue: QueuedTask[] = [];

  constructor(maxConcurrency: number = 2) {
    this.maxConcurrency = maxConcurrency;
  }

  public setMaxConcurrency(max: number): void {
    this.maxConcurrency = Math.max(1, max);
    this.processQueue();
  }

  public schedule(
    analyzer: Analyzer,
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    return new Promise<AnalysisResult>((resolve, reject) => {
      const taskId = `${analyzer.id}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      
      const task: QueuedTask = {
        id: taskId,
        analyzer,
        input,
        options,
        context,
        resolve,
        reject
      };

      if (context.signal?.aborted) {
        reject(new AbortedError());
        return;
      }

      this.queue.push(task);
      this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
    if (this.runningCount >= this.maxConcurrency || this.queue.length === 0) {
      return;
    }

    const task = this.queue.shift();
    if (!task) return;

    if (task.context.signal?.aborted) {
      task.reject(new AbortedError());
      this.processQueue();
      return;
    }

    this.runningCount++;

    try {
      const startTime = performance.now();
      const result = await task.analyzer.run(task.input, task.options, task.context);
      if (!result.durationMs) {
        result.durationMs = Math.round(performance.now() - startTime);
      }
      task.resolve(result);
    } catch (err) {
      task.reject(err);
    } finally {
      this.runningCount--;
      this.processQueue();
    }
  }

  public getQueueLength(): number {
    return this.queue.length;
  }

  public getActiveCount(): number {
    return this.runningCount;
  }
}

export const defaultScheduler = new TaskScheduler(2);
