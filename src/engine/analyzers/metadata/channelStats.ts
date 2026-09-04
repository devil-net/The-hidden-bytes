/**
 * The Hidden Bytes V2 - ImageMagick-style Channel Statistics Engine
 * Computes exact Minimum, Maximum, Mean, and Standard Deviation (raw, 16-bit, normalized)
 * for Red, Green, Blue, Alpha, and Overall Luminance.
 */

export interface ChannelStat {
  min: number;
  min16: number;
  minNorm: number;
  max: number;
  max16: number;
  maxNorm: number;
  mean: number;
  mean16: number;
  meanNorm: number;
  standardDeviation: number;
  standardDeviation16: number;
  standardDeviationNorm: number;
}

export interface ImageMagickMetadata {
  format: string;
  geometry: string;
  width: number;
  height: number;
  totalPixels: number;
  aspectRatio: string;
  classType: string;
  type: string;
  depth: string;
  channelDepths: {
    red: string;
    green: string;
    blue: string;
    alpha?: string;
  };
  channelStatistics: {
    red: ChannelStat;
    green: ChannelStat;
    blue: ChannelStat;
    alpha?: ChannelStat;
    overall: ChannelStat;
  };
  hasAlpha: boolean;
  interlace: string;
  colorspace: string;
  backgroundColor: string;
  borderColor: string;
  matteColor: string;
  pageGeometry: string;
}

export function computeChannelStatistics(
  data: Uint8ClampedArray | Uint8Array,
  width: number,
  height: number,
  formatName: string = 'JPEG',
  isProgressive: boolean = false
): ImageMagickMetadata {
  const totalPixels = width * height;
  const numSamples = data.length / 4;

  let minR = 255, maxR = 0, sumR = 0, sqSumR = 0;
  let minG = 255, maxG = 0, sumG = 0, sqSumG = 0;
  let minB = 255, maxB = 0, sumB = 0, sqSumB = 0;
  let minA = 255, maxA = 0, sumA = 0, sqSumA = 0;
  let hasTranslucent = false;

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];
    const a = data[i + 3];

    if (r < minR) minR = r;
    if (r > maxR) maxR = r;
    sumR += r;
    sqSumR += r * r;

    if (g < minG) minG = g;
    if (g > maxG) maxG = g;
    sumG += g;
    sqSumG += g * g;

    if (b < minB) minB = b;
    if (b > maxB) maxB = b;
    sumB += b;
    sqSumB += b * b;

    if (a < minA) minA = a;
    if (a > maxA) maxA = a;
    sumA += a;
    sqSumA += a * a;

    if (a < 255) hasTranslucent = true;
  }

  const n = numSamples || 1;

  const buildStat = (min: number, max: number, sum: number, sqSum: number): ChannelStat => {
    const mean = sum / n;
    const variance = Math.max(0, (sqSum / n) - (mean * mean));
    const stdDev = Math.sqrt(variance);

    // 16-bit scaling (ImageMagick scale: 65535 / 255 = 257.0)
    const scale16 = 65535 / 255;

    return {
      min,
      min16: Math.round(min * scale16),
      minNorm: parseFloat((min / 255).toFixed(4)),
      max,
      max16: Math.round(max * scale16),
      maxNorm: parseFloat((max / 255).toFixed(4)),
      mean: parseFloat(mean.toFixed(2)),
      mean16: parseFloat((mean * scale16).toFixed(2)),
      meanNorm: parseFloat((mean / 255).toFixed(4)),
      standardDeviation: parseFloat(stdDev.toFixed(2)),
      standardDeviation16: parseFloat((stdDev * scale16).toFixed(2)),
      standardDeviationNorm: parseFloat((stdDev / 255).toFixed(4))
    };
  };

  const redStat = buildStat(minR, maxR, sumR, sqSumR);
  const greenStat = buildStat(minG, maxG, sumG, sqSumG);
  const blueStat = buildStat(minB, maxB, sumB, sqSumB);
  const alphaStat = buildStat(minA, maxA, sumA, sqSumA);

  const totalSumAll = sumR + sumG + sumB;
  const totalSqSumAll = sqSumR + sqSumG + sqSumB;
  const overallStat = buildStat(
    Math.min(minR, minG, minB),
    Math.max(maxR, maxG, maxB),
    totalSumAll / 3,
    totalSqSumAll / 3
  );

  const gcd = (a: number, b: number): number => (b === 0 ? a : gcd(b, a % b));
  const divisor = gcd(width, height);
  const aspect = divisor > 0 ? `${width / divisor}:${height / divisor}` : '1:1';

  return {
    format: formatName,
    geometry: `${width}x${height}`,
    width,
    height,
    totalPixels,
    aspectRatio: aspect,
    classType: 'DirectClass',
    type: hasTranslucent ? 'TrueColorAlpha (RGBA)' : 'TrueColor (RGB)',
    depth: '8 bits-per-pixel component',
    channelDepths: {
      red: '8 bits',
      green: '8 bits',
      blue: '8 bits',
      ...(hasTranslucent ? { alpha: '8 bits' } : {})
    },
    channelStatistics: {
      red: redStat,
      green: greenStat,
      blue: blueStat,
      ...(hasTranslucent || minA < 255 ? { alpha: alphaStat } : {}),
      overall: overallStat
    },
    hasAlpha: hasTranslucent,
    interlace: isProgressive ? 'JPEG Progressive / Adam7' : 'No',
    colorspace: 'sRGB / DirectClass',
    backgroundColor: '#FFFFFF (white)',
    borderColor: '#DFDFDF',
    matteColor: '#BDBDBD',
    pageGeometry: `${width}x${height}+0+0`
  };
}
