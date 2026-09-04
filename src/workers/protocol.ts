/**
 * The Hidden Bytes V2 - Web Worker Communication Protocol
 */

import { AnalysisResult, AnalyzerOptions } from '../engine/types';

export type WorkerRequest = {
  id: string;
  type: 'RUN_ANALYZER';
  analyzerId: string;
  data: ArrayBuffer;
  options: AnalyzerOptions;
};

export type WorkerResponse =
  | {
      id: string;
      type: 'RESULT';
      result: AnalysisResult;
    }
  | {
      id: string;
      type: 'PROGRESS';
      progress: number;
      statusText: string;
    }
  | {
      id: string;
      type: 'ERROR';
      error: {
        code: string;
        message: string;
        details?: any;
      };
    };
