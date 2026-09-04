/**
 * The Hidden Bytes V2 - Error Hierarchy
 */

export class AnalysisEngineError extends Error {
  readonly code: string;
  readonly details?: any;

  constructor(message: string, code: string = 'ANALYSIS_ERROR', details?: any) {
    super(message);
    this.name = 'AnalysisEngineError';
    this.code = code;
    this.details = details;
  }
}

export class TimeoutError extends AnalysisEngineError {
  constructor(timeoutMs: number) {
    super(`Analysis timed out after ${timeoutMs}ms`, 'TIMEOUT_EXCEEDED', { timeoutMs });
    this.name = 'TimeoutError';
  }
}

export class QuotaExceededError extends AnalysisEngineError {
  constructor(limitBytes: number, actualBytes: number) {
    super(
      `Extraction quota exceeded: tried to extract ${actualBytes} bytes (limit: ${limitBytes} bytes)`,
      'QUOTA_EXCEEDED',
      { limitBytes, actualBytes }
    );
    this.name = 'QuotaExceededError';
  }
}

export class UnsupportedFormatError extends AnalysisEngineError {
  constructor(format: string, analyzerName: string) {
    super(`Format '${format}' is not supported by ${analyzerName}`, 'UNSUPPORTED_FORMAT', {
      format,
      analyzerName
    });
    this.name = 'UnsupportedFormatError';
  }
}

export class CorruptedFileError extends AnalysisEngineError {
  constructor(details: string) {
    super(`File header or structure is corrupted: ${details}`, 'CORRUPTED_FILE', { details });
    this.name = 'CorruptedFileError';
  }
}

export class AbortedError extends AnalysisEngineError {
  constructor() {
    super('Analysis was aborted by the user', 'ABORTED');
    this.name = 'AbortedError';
  }
}
