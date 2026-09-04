/**
 * The Hidden Bytes V2 - Core Engine Type Definitions
 */

export type AnalyzerImplementationType = 'native-ts' | 'wasm' | 'runtime' | 'compatible';

export interface FileDescriptor {
  name: string;
  size: number;
  type: string;
  lastModified?: number;
}

export interface Finding {
  offset?: number;
  length?: number;
  type: string;
  description: string;
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  metadata?: Record<string, any>;
}

export interface ExtractedFile {
  name: string;
  path: string;
  size: number;
  mimeType?: string;
  data: Uint8Array;
  sha256?: string;
  previewText?: string;
  isText?: boolean;
}

export interface AnalyzerError {
  code: string;
  message: string;
  details?: any;
}

export interface AnalysisResult {
  analyzerId: string;
  analyzerName: string;
  implementation: AnalyzerImplementationType;
  version: string;
  success: boolean;
  durationMs: number;
  findings: Finding[];
  files: ExtractedFile[];
  stdout?: string;
  stderr?: string;
  warnings: string[];
  error?: AnalyzerError;
  data?: Record<string, any>; // Tool-specific structured payloads (e.g. RGB channel data, EXIF trees)
}

export interface AnalyzerOptions {
  password?: string;
  offset?: number;
  length?: number;
  minStringLength?: number;
  encoding?: 'ascii' | 'utf-8' | 'utf-16le' | 'utf-16be';
  channels?: ('r' | 'g' | 'b' | 'a')[];
  bitPlanes?: number[];
  extractFiles?: boolean;
  maxExtractedBytes?: number;
  timeoutMs?: number;
  [key: string]: any;
}

export interface AnalyzerContext {
  signal?: AbortSignal;
  onProgress?: (progress: number, statusText: string) => void;
  onLog?: (message: string, level?: 'info' | 'warn' | 'error') => void;
}

export interface Analyzer {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly type: AnalyzerImplementationType;
  readonly description: string;
  readonly supportedMimeTypes?: string[];
  readonly supportedExtensions?: string[];

  supports(file: FileDescriptor): boolean;
  run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    options: AnalyzerOptions,
    context: AnalyzerContext
  ): Promise<AnalysisResult>;
}
