/**
 * The Hidden Bytes V2 - Web Worker Client Pool
 */

import { WorkerRequest, WorkerResponse } from './protocol';
import { AnalysisResult, AnalyzerOptions, AnalyzerContext } from '../engine/types';

export class WorkerClient {
  private worker: Worker | null = null;
  private pendingRequests: Map<
    string,
    {
      resolve: (res: AnalysisResult) => void;
      reject: (err: any) => void;
      context: AnalyzerContext;
    }
  > = new Map();

  constructor() {
    this.initWorker();
  }

  private initWorker(): void {
    if (typeof Worker !== 'undefined') {
      try {
        this.worker = new Worker(new URL('./analyzer.worker.ts', import.meta.url), {
          type: 'module'
        });

        this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
          const msg = e.data;
          const pending = this.pendingRequests.get(msg.id);
          if (!pending) return;

          if (msg.type === 'PROGRESS') {
            pending.context.onProgress?.(msg.progress, msg.statusText);
          } else if (msg.type === 'RESULT') {
            this.pendingRequests.delete(msg.id);
            pending.resolve(msg.result);
          } else if (msg.type === 'ERROR') {
            this.pendingRequests.delete(msg.id);
            pending.reject(new Error(msg.error.message));
          }
        };

        this.worker.onerror = (err) => {
          console.error('Worker runtime error:', err);
        };
      } catch (err) {
        console.warn('Web Workers unavailable or failed to initialize:', err);
      }
    }
  }

  public async runInWorker(
    analyzerId: string,
    data: ArrayBuffer,
    options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    if (!this.worker) {
      throw new Error('Web Worker is not active');
    }

    const requestId = `${analyzerId}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;

    return new Promise<AnalysisResult>((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject, context });

      const req: WorkerRequest = {
        id: requestId,
        type: 'RUN_ANALYZER',
        analyzerId,
        data,
        options
      };

      // Transfer ArrayBuffer ownership to worker for zero-copy high performance
      this.worker?.postMessage(req, [data]);
    });
  }

  public terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.pendingRequests.clear();
  }
}

export const workerClient = new WorkerClient();
