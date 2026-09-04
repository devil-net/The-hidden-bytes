/**
 * The Hidden Bytes V2 - Comprehensive Local Metadata & Forensic Header Extractor
 * Replaces backend exifread, PyPDF2, mutagen, and python-magic with 100% in-browser parsing.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { toUint8Array, calculateSha256 } from '../../../utils/crypto';
import ExifReader from 'exifreader';

export class MetadataAnalyzer implements Analyzer {
  readonly id = 'metadata';
  readonly name = 'Metadata';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'Extracts EXIF, XMP, IPTC, GPS, PDF dictionary, and ID3 audio tags without external requests.';

  supports(_file: FileDescriptor): boolean {
    return true;
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    _options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const totalBytes = bytes.length;
    const findings: Finding[] = [];
    const metadataTree: Record<string, any> = {};

    context.onProgress?.(10, 'Computing cryptographic file hashes...');

    const sha256 = await calculateSha256(bytes);
    
    metadataTree['File Information'] = {
      'File Size': `${totalBytes.toLocaleString()} bytes (${(totalBytes / (1024 * 1024)).toFixed(2)} MB)`,
      'SHA-256': sha256
    };

    if (input instanceof File) {
      metadataTree['File Information']['Filename'] = input.name;
      metadataTree['File Information']['MIME Type'] = input.type || 'application/octet-stream';
      metadataTree['File Information']['Last Modified'] = new Date(input.lastModified).toISOString();
    }

    context.onProgress?.(30, 'Parsing EXIF, XMP, IPTC and ICC tags...');

    try {
      const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      const tags = ExifReader.load(buffer, { expanded: true });

      if (tags.exif) {
        const exifData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.exif)) {
          exifData[key] = (tag as any).description;
        }
        metadataTree['EXIF'] = exifData;

        if (exifData['Software']) {
          findings.push({
            type: 'SOFTWARE_METADATA',
            description: `Editing software signature found: "${exifData['Software']}"`
          });
        }
      }

      if (tags.gps && Object.keys(tags.gps).length > 0) {
        const gpsData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.gps)) {
          gpsData[key] = (tag as any).description;
        }
        metadataTree['GPS Location'] = gpsData;

        findings.push({
          type: 'GPS_COORDINATES_FOUND',
          severity: 'high',
          description: `Geolocation metadata present: Latitude ${gpsData['Latitude'] || ''}, Longitude ${gpsData['Longitude'] || ''}`
        });
      }

      if (tags.xmp) {
        const xmpData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.xmp)) {
          xmpData[key] = (tag as any).description;
        }
        metadataTree['XMP Metadata'] = xmpData;
      }

      if (tags.iptc) {
        const iptcData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.iptc)) {
          iptcData[key] = (tag as any).description;
        }
        metadataTree['IPTC'] = iptcData;
      }

      if (tags.pngText) {
        const pngChunks: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.pngText)) {
          pngChunks[key] = (tag as any).description;
        }
        metadataTree['PNG Text Chunks'] = pngChunks;

        findings.push({
          type: 'PNG_TEXT_CHUNKS',
          severity: 'medium',
          description: `Found ${Object.keys(pngChunks).length} embedded PNG textual metadata chunks (e.g. tEXt / zTXt).`
        });
      }

      const anyTags = tags as any;
      if (anyTags.id3) {
        const id3Data: Record<string, any> = {};
        for (const [key, tag] of Object.entries(anyTags.id3)) {
          id3Data[key] = (tag as any)?.description || String(tag);
        }
        metadataTree['ID3 Audio Tags'] = id3Data;
      }
    } catch {
      // Ignored
    }

    context.onProgress?.(70, 'Scanning container dictionary metadata...');

    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
      const pdfText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 100000)));
      const pdfMeta: Record<string, string> = {};

      const titleMatch = /\/Title\s*\(([^)]+)\)/i.exec(pdfText);
      const authorMatch = /\/Author\s*\(([^)]+)\)/i.exec(pdfText);
      const creatorMatch = /\/Creator\s*\(([^)]+)\)/i.exec(pdfText);
      const producerMatch = /\/Producer\s*\(([^)]+)\)/i.exec(pdfText);
      const creationDateMatch = /\/CreationDate\s*\(([^)]+)\)/i.exec(pdfText);

      if (titleMatch) pdfMeta['Title'] = titleMatch[1];
      if (authorMatch) pdfMeta['Author'] = authorMatch[1];
      if (creatorMatch) pdfMeta['Creator'] = creatorMatch[1];
      if (producerMatch) pdfMeta['Producer'] = producerMatch[1];
      if (creationDateMatch) pdfMeta['Creation Date'] = creationDateMatch[1];

      if (Object.keys(pdfMeta).length > 0) {
        metadataTree['PDF Document Info'] = pdfMeta;
        findings.push({
          type: 'PDF_METADATA',
          description: `PDF Document metadata extracted (Author: ${pdfMeta['Author'] || 'N/A'}, Creator: ${pdfMeta['Creator'] || 'N/A'})`
        });
      }
    }

    context.onProgress?.(100, 'Metadata extraction complete');

    return {
      analyzerId: this.id,
      analyzerName: this.name,
      implementation: this.type,
      version: this.version,
      success: true,
      durationMs: Math.round(performance.now() - startTime),
      findings,
      files: [],
      warnings: [],
      data: {
        metadata: metadataTree,
        sha256
      }
    };
  }
}
