/**
 * The Hidden Bytes V2 - In-Memory Virtual File System (VFS)
 * Provides a sandboxed Linux-like filesystem in browser RAM.
 */

import { QuotaExceededError } from './errors';

export interface VFSFile {
  name: string;
  path: string;
  data: Uint8Array;
  size: number;
  lastModified: number;
}

export interface VFSOptions {
  maxTotalBytes?: number; // Default 200MB safety ceiling in RAM
  maxFileBytes?: number;  // Default 100MB per single file
}

export class VirtualFileSystem {
  private files: Map<string, VFSFile> = new Map();
  private totalBytes: number = 0;
  private readonly maxTotalBytes: number;
  private readonly maxFileBytes: number;

  constructor(options: VFSOptions = {}) {
    this.maxTotalBytes = options.maxTotalBytes ?? 200 * 1024 * 1024;
    this.maxFileBytes = options.maxFileBytes ?? 100 * 1024 * 1024;
  }

  private normalizePath(path: string): string {
    let normalized = path.replace(/\\/g, '/');
    if (!normalized.startsWith('/')) {
      normalized = '/' + normalized;
    }
    // Remove redundant slashes and resolve . / ..
    const parts = normalized.split('/').filter(p => p.length > 0 && p !== '.');
    const resolvedParts: string[] = [];
    for (const part of parts) {
      if (part === '..') {
        resolvedParts.pop();
      } else {
        resolvedParts.push(part);
      }
    }
    return '/' + resolvedParts.join('/');
  }

  public writeFile(path: string, data: Uint8Array | ArrayBuffer): void {
    const normalized = this.normalizePath(path);
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

    if (bytes.byteLength > this.maxFileBytes) {
      throw new QuotaExceededError(this.maxFileBytes, bytes.byteLength);
    }

    const existing = this.files.get(normalized);
    const prevSize = existing ? existing.size : 0;
    const newTotal = this.totalBytes - prevSize + bytes.byteLength;

    if (newTotal > this.maxTotalBytes) {
      throw new QuotaExceededError(this.maxTotalBytes, newTotal);
    }

    const filename = normalized.split('/').pop() || 'file';
    this.files.set(normalized, {
      name: filename,
      path: normalized,
      data: bytes,
      size: bytes.byteLength,
      lastModified: Date.now()
    });

    this.totalBytes = newTotal;
  }

  public readFile(path: string): Uint8Array {
    const normalized = this.normalizePath(path);
    const file = this.files.get(normalized);
    if (!file) {
      throw new Error(`VFS Error: File not found: ${normalized}`);
    }
    return file.data;
  }

  public exists(path: string): boolean {
    const normalized = this.normalizePath(path);
    return this.files.has(normalized);
  }

  public removeFile(path: string): boolean {
    const normalized = this.normalizePath(path);
    const file = this.files.get(normalized);
    if (file) {
      this.totalBytes -= file.size;
      return this.files.delete(normalized);
    }
    return false;
  }

  public listFiles(dirPath: string = '/'): VFSFile[] {
    const normalized = this.normalizePath(dirPath);
    const prefix = normalized === '/' ? '/' : normalized + '/';
    const result: VFSFile[] = [];

    for (const [path, file] of this.files.entries()) {
      if (normalized === '/' || path.startsWith(prefix)) {
        result.push(file);
      }
    }
    return result;
  }

  public clear(): void {
    this.files.clear();
    this.totalBytes = 0;
  }

  public getTotalBytes(): number {
    return this.totalBytes;
  }
}
