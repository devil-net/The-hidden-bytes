/**
 * The Hidden Bytes V2 - Magic Bytes & Signature Database
 */

export interface MagicSignature {
  name: string;
  category: 'archive' | 'image' | 'audio' | 'video' | 'executable' | 'document' | 'filesystem';
  extension: string;
  mimeType: string;
  magic: number[];
  mask?: number[];
  offset?: number; // Default 0 (can match anywhere in file during deep scan)
  description: string;
  trailer?: number[]; // File format termination marker (e.g. IEND chunk for PNG, EOI for JPEG)
}

export const SIGNATURES: MagicSignature[] = [
  // Images
  {
    name: 'PNG image',
    category: 'image',
    extension: 'png',
    mimeType: 'image/png',
    magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    description: 'Portable Network Graphics (PNG) image',
    trailer: [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82] // IEND chunk
  },
  {
    name: 'JPEG image',
    category: 'image',
    extension: 'jpg',
    mimeType: 'image/jpeg',
    magic: [0xFF, 0xD8, 0xFF],
    description: 'JPEG/JFIF standard image',
    trailer: [0xFF, 0xD9] // EOI (End of Image)
  },
  {
    name: 'GIF image',
    category: 'image',
    extension: 'gif',
    mimeType: 'image/gif',
    magic: [0x47, 0x49, 0x46, 0x38],
    description: 'Graphics Interchange Format (GIF87a/89a)',
    trailer: [0x3B] // GIF trailer
  },
  {
    name: 'BMP image',
    category: 'image',
    extension: 'bmp',
    mimeType: 'image/bmp',
    magic: [0x42, 0x4D],
    description: 'Windows Bitmap graphic'
  },
  {
    name: 'WebP image / RIFF container',
    category: 'image',
    extension: 'webp',
    mimeType: 'image/webp',
    magic: [0x52, 0x49, 0x46, 0x46],
    description: 'RIFF container (WebP/WAV/AVI)'
  },

  // Archives & Compressed
  {
    name: 'ZIP archive',
    category: 'archive',
    extension: 'zip',
    mimeType: 'application/zip',
    magic: [0x50, 0x4B, 0x03, 0x04],
    description: 'Standard PKZip compressed archive',
    trailer: [0x50, 0x4B, 0x05, 0x06] // EOCD
  },
  {
    name: 'GZIP compressed data',
    category: 'archive',
    extension: 'gz',
    mimeType: 'application/gzip',
    magic: [0x1F, 0x8B, 0x08],
    description: 'GZIP compressed stream'
  },
  {
    name: '7-Zip archive',
    category: 'archive',
    extension: '7z',
    mimeType: 'application/x-7z-compressed',
    magic: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
    description: '7-Zip LZMA archive'
  },
  {
    name: 'RAR archive',
    category: 'archive',
    extension: 'rar',
    mimeType: 'application/x-rar-compressed',
    magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
    description: 'RAR compressed archive'
  },
  {
    name: 'BZIP2 compressed data',
    category: 'archive',
    extension: 'bz2',
    mimeType: 'application/x-bzip2',
    magic: [0x42, 0x5A, 0x68],
    description: 'BZip2 compressed stream'
  },
  {
    name: 'XZ compressed data',
    category: 'archive',
    extension: 'xz',
    mimeType: 'application/x-xz',
    magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
    description: 'XZ LZMA2 compressed stream'
  },
  {
    name: 'ZLIB compressed stream',
    category: 'archive',
    extension: 'zlib',
    mimeType: 'application/zlib',
    magic: [0x78, 0x9C], // Default compression
    description: 'ZLIB stream (RFC 1950, default compression)'
  },
  {
    name: 'ZLIB compressed stream (Best)',
    category: 'archive',
    extension: 'zlib',
    mimeType: 'application/zlib',
    magic: [0x78, 0xDA], // Best compression
    description: 'ZLIB stream (RFC 1950, best compression)'
  },

  // Documents
  {
    name: 'PDF document',
    category: 'document',
    extension: 'pdf',
    mimeType: 'application/pdf',
    magic: [0x25, 0x50, 0x44, 0x46],
    description: 'Adobe Portable Document Format (PDF)',
    trailer: [0x25, 0x25, 0x45, 0x4F, 0x46] // %%EOF
  },
  {
    name: 'SQLite Database',
    category: 'document',
    extension: 'sqlite',
    mimeType: 'application/x-sqlite3',
    magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00],
    description: 'SQLite 3 Database file'
  },

  // Executables
  {
    name: 'ELF binary',
    category: 'executable',
    extension: 'elf',
    mimeType: 'application/x-executable',
    magic: [0x7F, 0x45, 0x4C, 0x46],
    description: 'Executable and Linkable Format (Linux/Unix executable)'
  },
  {
    name: 'Windows PE executable',
    category: 'executable',
    extension: 'exe',
    mimeType: 'application/x-dosexec',
    magic: [0x4D, 0x5A],
    description: 'DOS/Windows PE Portable Executable'
  },

  // Audio / Media
  {
    name: 'MP3 with ID3v2 tag',
    category: 'audio',
    extension: 'mp3',
    mimeType: 'audio/mpeg',
    magic: [0x49, 0x44, 0x33],
    description: 'MPEG Audio Layer III with ID3v2 metadata'
  },
  {
    name: 'FLAC audio',
    category: 'audio',
    extension: 'flac',
    mimeType: 'audio/flac',
    magic: [0x66, 0x4C, 0x61, 0x43],
    description: 'Free Lossless Audio Codec'
  },
  {
    name: 'Ogg container',
    category: 'audio',
    extension: 'ogg',
    mimeType: 'audio/ogg',
    magic: [0x4F, 0x67, 0x67, 0x53],
    description: 'Ogg multimedia container'
  }
];
