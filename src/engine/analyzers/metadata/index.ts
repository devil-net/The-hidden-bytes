/**
 * The Hidden Bytes V2 - Comprehensive Local Metadata & Forensic Header Extractor
 * Eliminates redundant categories to provide a clean, non-overwhelming, high-signal forensic view.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { toUint8Array, calculateSha256 } from '../../../utils/crypto';
import ExifReader from 'exifreader';
import { parseJpegStream, JpegInfo, JpegComment } from './jpeg';
import { computeChannelStatistics, ImageMagickMetadata } from './channelStats';
import { analyzeStegoHints, DecodedStegoHint } from './stegoHints';

export class MetadataAnalyzer implements Analyzer {
  readonly id = 'metadata';
  readonly name = 'Metadata';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'Extracts ImageMagick channel statistics, JPEG comments, Base64 stego hints, EXIF, GPS, XMP, IPTC, and container headers without redundant data.';

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
    const decodedStegoHints: DecodedStegoHint[] = [];
    const allComments: Array<{ source: string; text: string; offset?: number }> = [];

    context.onProgress?.(10, 'Computing cryptographic hashes & signatures...');
    const sha256 = await calculateSha256(bytes);
    
    // 1. JPEG Stream Deep Marker & Comment Analysis
    context.onProgress?.(25, 'Parsing binary stream & JPEG markers...');
    const jpegInfo: JpegInfo = parseJpegStream(bytes);
    if (jpegInfo.comments.length > 0) {
      jpegInfo.comments.forEach((c: JpegComment, idx: number) => {
        const key = jpegInfo.comments.length === 1 ? 'JPEG Comment' : `JPEG Comment [${idx + 1}]`;
        allComments.push({ source: key, text: c.text, offset: c.offset });

        const hint = analyzeStegoHints(key, c.text);
        if (hint) decodedStegoHints.push(hint);
      });
    }

    // 2. Scan GIF Comments (0x21 0xFE)
    if (bytes.length > 10 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) {
      for (let i = 0; i < bytes.length - 3; i++) {
        if (bytes[i] === 0x21 && bytes[i + 1] === 0xFE) {
          const blockLen = bytes[i + 2];
          if (blockLen > 0 && i + 3 + blockLen <= bytes.length) {
            const commentBytes = bytes.subarray(i + 3, i + 3 + blockLen);
            const text = new TextDecoder('latin1').decode(commentBytes).trim();
            if (text.length > 0) {
              allComments.push({ source: 'GIF Comment Extension', text, offset: i });
              const hint = analyzeStegoHints('GIF Comment', text);
              if (hint) decodedStegoHints.push(hint);
            }
          }
        }
      }
    }

    // 3. EXIF, XMP, IPTC, PNG Text chunks
    context.onProgress?.(45, 'Parsing EXIF, XMP, IPTC and ICC tags...');
    let exifClean: Record<string, any> | null = null;
    let gpsClean: Record<string, any> | null = null;
    let xmpClean: Record<string, any> | null = null;
    let iptcClean: Record<string, any> | null = null;
    let pngClean: Record<string, any> | null = null;
    let id3Clean: Record<string, any> | null = null;

    try {
      const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      const tags = ExifReader.load(buffer, { expanded: true });

      if (tags.exif) {
        const exifData: Record<string, any> = {};
        const redundantExifKeys = new Set([
          'Image Width', 'Image Height', 'ImageWidth', 'ImageHeight', 'PixelXDimension', 'PixelYDimension',
          'Bits Per Sample', 'BitsPerSample', 'Compression', 'ColorSpace', 'Thumbnail'
        ]);

        for (const [key, tag] of Object.entries(tags.exif)) {
          const desc = (tag as any).description;
          if (key.toLowerCase().includes('comment') || key === 'ImageDescription' || key === 'Artist' || key === 'Copyright') {
            allComments.push({ source: `EXIF ${key}`, text: String(desc) });
            const hint = analyzeStegoHints(`EXIF ${key}`, String(desc));
            if (hint) decodedStegoHints.push(hint);
          }
          if (!redundantExifKeys.has(key)) {
            exifData[key] = desc;
          }
        }

        if (Object.keys(exifData).length > 0) {
          exifClean = exifData;
        }

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
        gpsClean = gpsData;

        findings.push({
          type: 'GPS_COORDINATES_FOUND',
          severity: 'high',
          description: `Geolocation metadata present: Latitude ${gpsData['Latitude'] || ''}, Longitude ${gpsData['Longitude'] || ''}`
        });
      }

      if (tags.xmp && Object.keys(tags.xmp).length > 0) {
        const xmpData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.xmp)) {
          const desc = (tag as any).description;
          xmpData[key] = desc;
          if (key.toLowerCase().includes('comment') || key.toLowerCase().includes('desc')) {
            allComments.push({ source: `XMP ${key}`, text: String(desc) });
          }
          const hint = analyzeStegoHints(`XMP ${key}`, String(desc));
          if (hint) decodedStegoHints.push(hint);
        }
        if (Object.keys(xmpData).length > 0) xmpClean = xmpData;
      }

      if (tags.iptc && Object.keys(tags.iptc).length > 0) {
        const iptcData: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.iptc)) {
          const desc = (tag as any).description;
          iptcData[key] = desc;
          if (key.toLowerCase().includes('caption') || key.toLowerCase().includes('comment')) {
            allComments.push({ source: `IPTC ${key}`, text: String(desc) });
          }
          const hint = analyzeStegoHints(`IPTC ${key}`, String(desc));
          if (hint) decodedStegoHints.push(hint);
        }
        if (Object.keys(iptcData).length > 0) iptcClean = iptcData;
      }

      if (tags.pngText && Object.keys(tags.pngText).length > 0) {
        const pngChunks: Record<string, any> = {};
        for (const [key, tag] of Object.entries(tags.pngText)) {
          const desc = (tag as any).description;
          pngChunks[key] = desc;
          allComments.push({ source: `PNG Chunk (${key})`, text: String(desc) });
          const hint = analyzeStegoHints(`PNG Chunk (${key})`, String(desc));
          if (hint) decodedStegoHints.push(hint);
        }
        pngClean = pngChunks;

        findings.push({
          type: 'PNG_TEXT_CHUNKS',
          severity: 'medium',
          description: `Found ${Object.keys(pngChunks).length} embedded PNG textual metadata chunks.`
        });
      }

      const anyTags = tags as any;
      if (anyTags.id3 && Object.keys(anyTags.id3).length > 0) {
        const id3Data: Record<string, any> = {};
        for (const [key, tag] of Object.entries(anyTags.id3)) {
          const desc = (tag as any)?.description || String(tag);
          id3Data[key] = desc;
          const hint = analyzeStegoHints(`ID3 ${key}`, String(desc));
          if (hint) decodedStegoHints.push(hint);
        }
        id3Clean = id3Data;
      }
    } catch {
      // Ignored
    }

    // 4. Image Raster Decoding & Channel Statistics
    let imageMagickMeta: ImageMagickMetadata | null = null;
    try {
      context.onProgress?.(65, 'Computing ImageMagick channel statistics & geometry...');
      const blob = new Blob([bytes.buffer as ArrayBuffer]);
      const isImage = (input instanceof File && input.type.startsWith('image/')) || jpegInfo.isJpeg || bytes[0] === 0x89;
      
      if (isImage && typeof createImageBitmap !== 'undefined') {
        const imgBitmap = await createImageBitmap(blob);
        const width = imgBitmap.width;
        const height = imgBitmap.height;

        let canvas: HTMLCanvasElement | OffscreenCanvas;
        let ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;

        if (typeof OffscreenCanvas !== 'undefined') {
          canvas = new OffscreenCanvas(width, height);
          ctx = canvas.getContext('2d') as OffscreenCanvasRenderingContext2D;
        } else if (typeof document !== 'undefined') {
          canvas = document.createElement('canvas');
          canvas.width = width;
          canvas.height = height;
          ctx = canvas.getContext('2d');
        } else {
          ctx = null;
        }

        if (ctx) {
          ctx.drawImage(imgBitmap, 0, 0);
          const imgData = ctx.getImageData(0, 0, width, height);
          imageMagickMeta = computeChannelStatistics(
            imgData.data,
            width,
            height,
            jpegInfo.isJpeg ? 'JPEG (Joint Photographic Experts Group JFIF format)' : 'Image (DirectClass)',
            jpegInfo.progressive || false
          );
        }
      }
    } catch {
      // Ignored for non-standard formats
    }

    // 5. PDF Metadata
    let pdfClean: Record<string, any> | null = null;
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x50) { // %PDF
      const pdfText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 100000)));
      const pdfMeta: Record<string, string> = {};

      const titleMatch = /\/Title\s*\(([^)]+)\)/i.exec(pdfText);
      const authorMatch = /\/Author\s*\(([^)]+)\)/i.exec(pdfText);
      const creatorMatch = /\/Creator\s*\(([^)]+)\)/i.exec(pdfText);
      const producerMatch = /\/Producer\s*\(([^)]+)\)/i.exec(pdfText);

      if (titleMatch) pdfMeta['Title'] = titleMatch[1];
      if (authorMatch) pdfMeta['Author'] = authorMatch[1];
      if (creatorMatch) pdfMeta['Creator'] = creatorMatch[1];
      if (producerMatch) pdfMeta['Producer'] = producerMatch[1];

      if (Object.keys(pdfMeta).length > 0) {
        pdfClean = pdfMeta;
      }
    }

    // 6. Assemble Unified Non-Redundant Metadata Tree
    // Section A: Image Properties & Geometry (ImageMagick Format)
    if (imageMagickMeta || jpegInfo.isJpeg) {
      const imgProps: Record<string, any> = {
        'Format': imageMagickMeta?.format || 'JPEG (Joint Photographic Experts Group JFIF format)',
        'Geometry': imageMagickMeta?.geometry || (jpegInfo.dimensions ? `${jpegInfo.dimensions.width}x${jpegInfo.dimensions.height}` : 'Unknown'),
        'Class': imageMagickMeta?.classType || 'DirectClass',
        'Type': imageMagickMeta?.type || 'TrueColor (RGB)',
        'Depth': imageMagickMeta?.depth || '8 bits-per-pixel component',
        'Channel Depths': imageMagickMeta ? `Red: ${imageMagickMeta.channelDepths.red}, Green: ${imageMagickMeta.channelDepths.green}, Blue: ${imageMagickMeta.channelDepths.blue}${imageMagickMeta.channelDepths.alpha ? `, Alpha: ${imageMagickMeta.channelDepths.alpha}` : ''}` : 'Red: 8 bits, Green: 8 bits, Blue: 8 bits',
        ...(jpegInfo.samplingFactorsString ? { 'JPEG Sampling Factors': jpegInfo.samplingFactorsString } : {}),
        ...(jpegInfo.estimatedQuality !== undefined ? { 'JPEG Quality': `${jpegInfo.estimatedQuality}%` } : {}),
        'Interlace': imageMagickMeta?.interlace || (jpegInfo.progressive ? 'Yes (Progressive)' : 'No'),
        'Page Geometry': imageMagickMeta?.pageGeometry || (jpegInfo.dimensions ? `${jpegInfo.dimensions.width}x${jpegInfo.dimensions.height}+0+0` : 'Unknown')
      };

      // Comments placed cleanly in Image Properties (once!)
      if (allComments.length > 0) {
        allComments.forEach((c, idx) => {
          const k = allComments.length === 1 ? 'Comment' : `Comment [${idx + 1}]`;
          imgProps[k] = c.text;
        });
      }

      if (imageMagickMeta) {
        imgProps['Background Color'] = imageMagickMeta.backgroundColor;
        imgProps['Border Color'] = imageMagickMeta.borderColor;
        imgProps['Matte Color'] = imageMagickMeta.matteColor;
      }

      metadataTree['Image Properties & Geometry'] = imgProps;
    }

    // Section B: Channel Statistics (ImageMagick Table)
    if (imageMagickMeta) {
      const stats = imageMagickMeta.channelStatistics;
      const formatChannel = (ch: any) => ({
        'Minimum': `${ch.min16}.00 (${ch.minNorm.toFixed(4)})`,
        'Maximum': `${ch.max16}.00 (${ch.maxNorm.toFixed(4)})`,
        'Mean': `${ch.mean16.toFixed(2)} (${ch.meanNorm.toFixed(4)})`,
        'Standard Deviation': `${ch.standardDeviation16.toFixed(2)} (${ch.standardDeviationNorm.toFixed(4)})`
      });

      const channelStatsObj: Record<string, any> = {
        'Red': formatChannel(stats.red),
        'Green': formatChannel(stats.green),
        'Blue': formatChannel(stats.blue)
      };
      if (stats.alpha) {
        channelStatsObj['Alpha'] = formatChannel(stats.alpha);
      }
      channelStatsObj['Overall Luminance'] = formatChannel(stats.overall);

      metadataTree['Channel Statistics (ImageMagick)'] = channelStatsObj;
    }

    // Section C: EXIF & Camera Metadata (Only non-empty)
    if (exifClean) metadataTree['EXIF & Camera Metadata'] = exifClean;

    // Section D: GPS Coordinates (Only if present)
    if (gpsClean) metadataTree['GPS Geolocation'] = gpsClean;

    // Section E: XMP / IPTC (Only if present)
    if (xmpClean) metadataTree['XMP Metadata'] = xmpClean;
    if (iptcClean) metadataTree['IPTC Metadata'] = iptcClean;
    if (pngClean) metadataTree['PNG Text Chunks'] = pngClean;
    if (id3Clean) metadataTree['ID3 Audio Tags'] = id3Clean;
    if (pdfClean) metadataTree['PDF Document Info'] = pdfClean;

    // Section F: File Hashes & Signatures
    const fileInfo: Record<string, any> = {
      'File Size': `${totalBytes.toLocaleString()} bytes (${(totalBytes / 1024).toFixed(2)} KB)`,
      'SHA-256': sha256
    };
    if (input instanceof File) {
      fileInfo['Filename'] = input.name;
      fileInfo['MIME Type'] = input.type || 'application/octet-stream';
      fileInfo['Last Modified'] = new Date(input.lastModified).toISOString();
    }
    // If not an image, comment goes in File Information
    if (!metadataTree['Image Properties & Geometry'] && allComments.length > 0) {
      allComments.forEach((c, idx) => {
        const k = allComments.length === 1 ? 'Comment' : `Comment [${idx + 1}]`;
        fileInfo[k] = c.text;
      });
    }
    metadataTree['File Information & Hashes'] = fileInfo;

    // Register Stego Findings
    if (decodedStegoHints.length > 0) {
      decodedStegoHints.forEach((hint) => {
        findings.push({
          type: 'STEGO_PASSPHRASE_HINT',
          severity: 'high',
          description: `Decoded steganography hint from ${hint.sourceField}: "${hint.finalDecodedText}" (Candidate Passphrase: "${hint.candidatePassphrase || hint.finalDecodedText}")`
        });
      });
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
        decodedStegoHints,
        allComments,
        imageMagick: imageMagickMeta,
        jpegInfo,
        sha256
      }
    };
  }
}
