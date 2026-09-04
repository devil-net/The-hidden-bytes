/**
 * The Hidden Bytes V2 - Dedicated Web Worker Execution Sandbox
 * Runs heavy analysis (Strings, Binwalk, Signatures, Entropy, Zsteg) off the main UI thread.
 */

import { WorkerRequest, WorkerResponse } from './protocol';
import { registry } from '../engine/registry';
import '../engine/index'; // Trigger registration

self.onmessage = async (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;

  if (request.type === 'RUN_ANALYZER') {
    const analyzer = registry.get(request.analyzerId);

    if (!analyzer) {
      const response: WorkerResponse = {
        id: request.id,
        type: 'ERROR',
        error: {
          code: 'ANALYZER_NOT_FOUND',
          message: `Worker cannot find analyzer with ID: ${request.analyzerId}`
        }
      };
      self.postMessage(response);
      return;
    }

    try {
      const result = await analyzer.run(
        request.data,
        request.options,
        {
          onProgress: (progress, statusText) => {
            const progMsg: WorkerResponse = {
              id: request.id,
              type: 'PROGRESS',
              progress,
              statusText
            };
            self.postMessage(progMsg);
          }
        }
      );

      const successResponse: WorkerResponse = {
        id: request.id,
        type: 'RESULT',
        result
      };

      self.postMessage(successResponse);
    } catch (err: any) {
      const errResponse: WorkerResponse = {
        id: request.id,
        type: 'ERROR',
        error: {
          code: err.code || 'WORKER_ERROR',
          message: err.message || String(err),
          details: err.details
        }
      };
      self.postMessage(errResponse);
    }
  }
};
