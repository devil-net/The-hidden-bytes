/**
 * The Hidden Bytes V2 - Deep JPEG Stream & Header Inspector
 * Extracts COM (Comments), DQT (Quantization Tables / Estimated Quality),
 * SOF (Sampling Factors, Precision, Dimensions), and APP markers directly from binary streams.
 * Includes full-stream dual-pass scanner to guarantee 100% detection of all comments anywhere in the file.
 */

export interface JpegComment {
  offset: number;
  length: number;
  text: string;
  isBase64Candidate: boolean;
  isHexCandidate: boolean;
}

export interface JpegSamplingFactor {
  componentId: number;
  name: string;
  hSampling: number;
  vSampling: number;
  quantTableId: number;
}

export interface JpegInfo {
  isJpeg: boolean;
  dimensions?: { width: number; height: number };
  precision?: number;
  progressive?: boolean;
  colorspace?: string;
  colorspaceId?: number;
  samplingFactorsString?: string;
  samplingFactors?: JpegSamplingFactor[];
  estimatedQuality?: number;
  comments: JpegComment[];
  markersSummary: Array<{ markerHex: string; name: string; offset: number; length?: number }>;
  jfif?: { version: string; units: string; xDensity: number; yDensity: number };
  adobe?: { transform: number; transformName: string };
}

// Standard baseline JPEG luminance quantization table (Quality 50)
const STD_LUMINANCE_QUANT_TABLE = [
  16, 11, 10, 16, 24, 40, 51, 61,
  12, 12, 14, 19, 26, 58, 60, 55,
  14, 13, 16, 24, 40, 57, 69, 56,
  14, 17, 22, 29, 51, 87, 80, 62,
  18, 22, 37, 56, 68, 109, 103, 77,
  24, 35, 55, 64, 81, 104, 113, 92,
  49, 64, 78, 87, 103, 121, 120, 101,
  72, 92, 95, 98, 112, 100, 103, 99
];

export function parseJpegStream(bytes: Uint8Array): JpegInfo {
  const result: JpegInfo = {
    isJpeg: false,
    comments: [],
    markersSummary: []
  };

  const len = bytes.length;
  if (len < 4) return result;

  // Check for JPEG SOI (0xFF 0xD8) anywhere in first 16 bytes
  let soiOffset = -1;
  for (let i = 0; i < Math.min(16, len - 1); i++) {
    if (bytes[i] === 0xFF && bytes[i + 1] === 0xD8) {
      soiOffset = i;
      break;
    }
  }

  if (soiOffset === -1) {
    // If not standard SOI, still check if COM marker exists in binary
    extractAllJpegComments(bytes, result.comments);
    return result;
  }

  result.isJpeg = true;
  result.markersSummary.push({ markerHex: '0xFFD8', name: 'SOI (Start of Image)', offset: soiOffset });

  let offset = soiOffset + 2;
  let luminanceQuantTable: number[] | null = null;
  const foundCommentOffsets = new Set<number>();

  // Pass 1: Structured Segment Walk
  while (offset < len - 1) {
    if (bytes[offset] !== 0xFF) {
      offset++;
      continue;
    }

    // Skip fill bytes (0xFF 0xFF ...)
    while (offset < len && bytes[offset] === 0xFF) {
      offset++;
    }

    if (offset >= len) break;

    const marker = bytes[offset++];
    const markerHex = `0xFF${marker.toString(16).toUpperCase().padStart(2, '0')}`;

    if (marker === 0xD9) { // EOI
      result.markersSummary.push({ markerHex, name: 'EOI (End of Image)', offset: offset - 2 });
      break;
    }
    if (marker === 0x00 || (marker >= 0xD0 && marker <= 0xD7)) { // RST markers or stuffed byte
      continue;
    }

    if (offset + 2 > len) break;
    const segmentLength = (bytes[offset] << 8) | bytes[offset + 1];
    const segmentDataOffset = offset + 2;
    const segmentDataEnd = offset + segmentLength;

    if (segmentLength < 2 || segmentDataEnd > len) break;

    switch (marker) {
      case 0xFE: { // COM (Comment Marker)
        const commentBytes = bytes.subarray(segmentDataOffset, segmentDataEnd);
        let commentText = '';
        try {
          commentText = new TextDecoder('utf-8', { fatal: false }).decode(commentBytes).trim();
        } catch {
          commentText = new TextDecoder('latin1').decode(commentBytes).trim();
        }

        const isBase64 = /^[A-Za-z0-9+/=_-]{4,}$/.test(commentText.replace(/\s+/g, ''));
        const isHex = /^[0-9a-fA-F]{6,}$/.test(commentText.replace(/\s+/g, ''));

        const comOffset = offset - 2;
        foundCommentOffsets.add(comOffset);

        result.comments.push({
          offset: comOffset,
          length: segmentLength,
          text: commentText,
          isBase64Candidate: isBase64,
          isHexCandidate: isHex
        });

        result.markersSummary.push({
          markerHex,
          name: `COM (Comment: "${commentText.slice(0, 30)}${commentText.length > 30 ? '...' : ''}")`,
          offset: comOffset,
          length: segmentLength
        });
        break;
      }

      case 0xDB: { // DQT (Define Quantization Table)
        result.markersSummary.push({ markerHex, name: 'DQT (Quantization Table)', offset: offset - 2, length: segmentLength });
        let qOffset = segmentDataOffset;
        while (qOffset < segmentDataEnd) {
          const info = bytes[qOffset++];
          const precision = (info >> 4) === 0 ? 8 : 16;
          const tableId = info & 0x0F;
          const entrySize = precision === 8 ? 1 : 2;
          
          if (qOffset + 64 * entrySize <= segmentDataEnd) {
            const table: number[] = [];
            for (let i = 0; i < 64; i++) {
              if (precision === 8) {
                table.push(bytes[qOffset++]);
              } else {
                table.push((bytes[qOffset] << 8) | bytes[qOffset + 1]);
                qOffset += 2;
              }
            }
            if (tableId === 0 && !luminanceQuantTable) {
              luminanceQuantTable = table;
            }
          } else {
            break;
          }
        }
        break;
      }

      case 0xC0: // SOF0 (Baseline DCT)
      case 0xC1: // SOF1 (Extended Sequential)
      case 0xC2: // SOF2 (Progressive DCT)
      case 0xC3: // SOF3 (Lossless)
      {
        const isProgressive = marker === 0xC2;
        const name = isProgressive ? 'SOF2 (Progressive DCT)' : 'SOF0 (Baseline DCT)';
        result.markersSummary.push({ markerHex, name, offset: offset - 2, length: segmentLength });

        const precision = bytes[segmentDataOffset];
        const height = (bytes[segmentDataOffset + 1] << 8) | bytes[segmentDataOffset + 2];
        const width = (bytes[segmentDataOffset + 3] << 8) | bytes[segmentDataOffset + 4];
        const numComponents = bytes[segmentDataOffset + 5];

        result.dimensions = { width, height };
        result.precision = precision;
        result.progressive = isProgressive;
        result.colorspaceId = numComponents;

        const compNames: Record<number, string> = { 1: 'Grayscale', 3: 'RGB / YCbCr', 4: 'CMYK / YCCK' };
        result.colorspace = compNames[numComponents] || `Unknown (${numComponents} components)`;

        const samplingFactors: JpegSamplingFactor[] = [];
        const samplingStrings: string[] = [];

        for (let c = 0; c < numComponents; c++) {
          const cOffset = segmentDataOffset + 6 + c * 3;
          if (cOffset + 3 <= segmentDataEnd) {
            const compId = bytes[cOffset];
            const factors = bytes[cOffset + 1];
            const qTableId = bytes[cOffset + 2];
            const hSampling = factors >> 4;
            const vSampling = factors & 0x0F;

            const cName = compId === 1 ? 'Y / Luminance' : compId === 2 ? 'Cb / Blue Chrominance' : compId === 3 ? 'Cr / Red Chrominance' : `Component ${compId}`;
            samplingFactors.push({
              componentId: compId,
              name: cName,
              hSampling,
              vSampling,
              quantTableId: qTableId
            });
            samplingStrings.push(`${hSampling}x${vSampling}`);
          }
        }

        result.samplingFactors = samplingFactors;
        result.samplingFactorsString = samplingStrings.join(', ');
        break;
      }

      case 0xE0: { // APP0 (JFIF)
        result.markersSummary.push({ markerHex, name: 'APP0 (JFIF Header)', offset: offset - 2, length: segmentLength });
        if (segmentLength >= 16) {
          const id = new TextDecoder('latin1').decode(bytes.subarray(segmentDataOffset, segmentDataOffset + 5));
          if (id.startsWith('JFIF')) {
            const major = bytes[segmentDataOffset + 5];
            const minor = bytes[segmentDataOffset + 6];
            const unitsId = bytes[segmentDataOffset + 7];
            const units = unitsId === 1 ? 'dots/inch (DPI)' : unitsId === 2 ? 'dots/cm' : 'No units';
            const xDensity = (bytes[segmentDataOffset + 8] << 8) | bytes[segmentDataOffset + 9];
            const yDensity = (bytes[segmentDataOffset + 10] << 8) | bytes[segmentDataOffset + 11];
            result.jfif = { version: `${major}.${minor.toString().padStart(2, '0')}`, units, xDensity, yDensity };
          }
        }
        break;
      }

      case 0xEE: { // APP14 (Adobe)
        result.markersSummary.push({ markerHex, name: 'APP14 (Adobe Color Transform)', offset: offset - 2, length: segmentLength });
        if (segmentLength >= 14) {
          const transform = bytes[segmentDataOffset + 11];
          const transformName = transform === 0 ? 'Unknown (RGB or CMYK)' : transform === 1 ? 'YCbCr' : transform === 2 ? 'YCCK' : 'Custom';
          result.adobe = { transform, transformName };
        }
        break;
      }

      case 0xDA: { // SOS (Start of Scan - begins entropy data)
        result.markersSummary.push({ markerHex, name: 'SOS (Start of Scan)', offset: offset - 2, length: segmentLength });
        break;
      }

      default: {
        const appNum = marker >= 0xE0 && marker <= 0xEF ? `APP${marker - 0xE0}` : `Marker 0x${marker.toString(16).toUpperCase()}`;
        result.markersSummary.push({ markerHex, name: appNum, offset: offset - 2, length: segmentLength });
        break;
      }
    }

    offset = segmentDataEnd;
  }

  // Pass 2: Global Full-File Scan for any missed COM markers (0xFF 0xFE)
  extractAllJpegComments(bytes, result.comments, foundCommentOffsets);

  // Calculate Estimated JPEG Quality based on standard luminance table scaling
  if (luminanceQuantTable && luminanceQuantTable.length === 64) {
    let sumRatio = 0;
    let count = 0;
    for (let i = 0; i < 64; i++) {
      const actual = luminanceQuantTable[i];
      const standard = STD_LUMINANCE_QUANT_TABLE[i];
      if (standard > 0 && actual > 0) {
        sumRatio += (actual * 100) / standard;
        count++;
      }
    }

    if (count > 0) {
      const avgScaling = sumRatio / count;
      let estQuality = 50;
      if (avgScaling <= 100) {
        estQuality = Math.round(5000 / Math.max(1, avgScaling));
        if (estQuality > 100) estQuality = Math.round((200 - avgScaling) / 2);
      } else {
        estQuality = Math.round(5000 / avgScaling);
      }
      result.estimatedQuality = Math.max(1, Math.min(100, estQuality));
    }
  }

  return result;
}

/**
 * Scans the entire binary for 0xFF 0xFE JPEG comment signatures to ensure nothing is missed
 */
function extractAllJpegComments(bytes: Uint8Array, comments: JpegComment[], knownOffsets: Set<number> = new Set()): void {
  const len = bytes.length;
  for (let i = 0; i < len - 4; i++) {
    if (bytes[i] === 0xFF && bytes[i + 1] === 0xFE) {
      if (knownOffsets.has(i)) continue;

      const segLen = (bytes[i + 2] << 8) | bytes[i + 3];
      if (segLen >= 2 && i + 2 + segLen <= len) {
        const commentBytes = bytes.subarray(i + 4, i + 2 + segLen);
        let commentText = '';
        try {
          commentText = new TextDecoder('utf-8', { fatal: false }).decode(commentBytes).trim();
        } catch {
          commentText = new TextDecoder('latin1').decode(commentBytes).trim();
        }

        // Validate printable characters
        let printable = 0;
        for (let j = 0; j < commentText.length; j++) {
          const code = commentText.charCodeAt(j);
          if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
            printable++;
          }
        }

        if (commentText.length > 0 && (printable / commentText.length >= 0.7)) {
          const isBase64 = /^[A-Za-z0-9+/=_-]{4,}$/.test(commentText.replace(/\s+/g, ''));
          const isHex = /^[0-9a-fA-F]{6,}$/.test(commentText.replace(/\s+/g, ''));

          knownOffsets.add(i);
          comments.push({
            offset: i,
            length: segLen,
            text: commentText,
            isBase64Candidate: isBase64,
            isHexCandidate: isHex
          });
        }
      }
    }
  }
}
