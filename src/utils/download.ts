/**
 * The Hidden Bytes V2 - Client-side File and ZIP Download Manager
 */

import { zipSync, Zippable } from 'fflate';
import { ExtractedFile } from '../engine/types';

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function downloadBytes(data: Uint8Array, filename: string, mimeType: string = 'application/octet-stream'): void {
  const blob = new Blob([data.buffer as ArrayBuffer], { type: mimeType });
  downloadBlob(blob, filename);
}

export function downloadExtractedFile(file: ExtractedFile): void {
  downloadBytes(file.data, file.name, file.mimeType || 'application/octet-stream');
}

export function downloadFilesAsZip(files: ExtractedFile[], zipFilename: string = 'hidden_bytes_extracted.zip'): void {
  if (files.length === 0) return;

  const zippableObj: Zippable = {};
  for (const file of files) {
    const cleanPath = file.path.replace(/^\/+/, '') || file.name;
    zippableObj[cleanPath] = file.data;
  }

  const zippedBytes = zipSync(zippableObj, { level: 6 });
  const blob = new Blob([zippedBytes.buffer as ArrayBuffer], { type: 'application/zip' });
  downloadBlob(blob, zipFilename);
}
