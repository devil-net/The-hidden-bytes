/**
 * The Hidden Bytes V2 - Cryptographic and Hashing Utilities (Web Crypto API)
 */

export async function calculateSha256(data: Uint8Array | ArrayBuffer): Promise<string> {
  const buffer = data instanceof Uint8Array ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer as ArrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function toUint8Array(input: Uint8Array | ArrayBuffer | Blob | File | unknown): Promise<Uint8Array> {
  if (input instanceof Uint8Array) {
    return Promise.resolve(input);
  }
  if (input instanceof ArrayBuffer) {
    return Promise.resolve(new Uint8Array(input));
  }
  if (input instanceof Blob) {
    return input.arrayBuffer().then(buf => new Uint8Array(buf));
  }
  throw new Error('Unsupported input type for toUint8Array');
}
