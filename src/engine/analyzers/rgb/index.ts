/**
 * The Hidden Bytes V2 - Browser-Native RGB Channel & Bit-Plane Analyzer
 * Replaces server-side Pillow & NumPy pipeline with 100% in-browser Canvas/ImageData processing.
 */

import { Analyzer, AnalysisResult, AnalyzerOptions, AnalyzerContext, FileDescriptor, Finding } from '../../types';
import { toUint8Array } from '../../../utils/crypto';

export class RGBAnalyzer implements Analyzer {
  readonly id = 'rgb';
  readonly name = 'RGB Viewer';
  readonly version = '2.0.0-browser';
  readonly type = 'native-ts' as const;
  readonly description = 'In-browser RGB color channel separation, bit-plane decomposition, and LSB visual analysis.';
  readonly supportedExtensions = ['png', 'jpg', 'jpeg', 'bmp', 'webp', 'gif'];

  supports(file: FileDescriptor): boolean {
    const ext = file.name.split('.').pop()?.toLowerCase() || '';
    return file.type.startsWith('image/') || this.supportedExtensions.includes(ext);
  }

  async run(
    input: File | Blob | Uint8Array | ArrayBuffer,
    _options: AnalyzerOptions = {},
    context: AnalyzerContext = {}
  ): Promise<AnalysisResult> {
    const startTime = performance.now();
    const bytes = await toUint8Array(input);
    const blob = new Blob([bytes.buffer as ArrayBuffer]);

    context.onProgress?.(10, 'Decoding image...');

    const imgBitmap = await createImageBitmap(blob);
    const width = imgBitmap.width;
    const height = imgBitmap.height;

    let canvas: HTMLCanvasElement | OffscreenCanvas;
    let ctx: CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D | null;

    if (typeof OffscreenCanvas !== 'undefined') {
      canvas = new OffscreenCanvas(width, height);
      ctx = canvas.getContext('2d') as OffscreenCanvasRenderingContext2D;
    } else {
      canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      ctx = canvas.getContext('2d');
    }

    if (!ctx) {
      throw new Error('Failed to get 2D canvas context for RGB analysis');
    }

    ctx.drawImage(imgBitmap, 0, 0);
    const rawImageData = ctx.getImageData(0, 0, width, height);
    const srcData = rawImageData.data;
    const totalPixels = width * height;

    context.onProgress?.(30, 'Calculating RGB histogram and bit planes...');

    const redHist = new Array(256).fill(0);
    const greenHist = new Array(256).fill(0);
    const blueHist = new Array(256).fill(0);

    let rLsbCount = 0;
    let gLsbCount = 0;
    let bLsbCount = 0;

    // Collect first 500 RGBA samples for inspector
    const rgbaSamples: Array<{ x: number; y: number; r: number; g: number; b: number; a: number }> = [];
    const sampleLimit = Math.min(500, totalPixels);

    for (let i = 0; i < srcData.length; i += 4) {
      const r = srcData[i];
      const g = srcData[i + 1];
      const b = srcData[i + 2];
      const a = srcData[i + 3];

      redHist[r]++;
      greenHist[g]++;
      blueHist[b]++;

      if (r & 1) rLsbCount++;
      if (g & 1) gLsbCount++;
      if (b & 1) bLsbCount++;

      if (rgbaSamples.length < sampleLimit) {
        const pixelIdx = i / 4;
        const x = pixelIdx % width;
        const y = Math.floor(pixelIdx / width);
        rgbaSamples.push({ x, y, r, g, b, a });
      }
    }

    const findings: Finding[] = [
      {
        type: 'DIMENSIONS',
        description: `Image dimensions: ${width}x${height} (${totalPixels.toLocaleString()} pixels)`
      }
    ];

    const rLsbRatio = rLsbCount / totalPixels;
    const gLsbRatio = gLsbCount / totalPixels;
    const bLsbRatio = bLsbCount / totalPixels;

    if (Math.abs(rLsbRatio - 0.5) < 0.02 && Math.abs(gLsbRatio - 0.5) < 0.02 && Math.abs(bLsbRatio - 0.5) < 0.02) {
      findings.push({
        type: 'LSB_ANOMALY',
        severity: 'medium',
        description: `Near-perfect uniform LSB distribution detected (R: ${(rLsbRatio * 100).toFixed(1)}%, G: ${(gLsbRatio * 100).toFixed(1)}%, B: ${(bLsbRatio * 100).toFixed(1)}%), suggesting potential LSB steganography.`
      });
    }

    context.onProgress?.(60, 'Generating channel transformations...');

    const generateTransformedDataUrl = (transformFn: (r: number, g: number, b: number, a: number, out: Uint8ClampedArray, idx: number) => void): string => {
      const helperCanvas = document.createElement('canvas');
      helperCanvas.width = width;
      helperCanvas.height = height;
      const helperCtx = helperCanvas.getContext('2d');
      if (!helperCtx) return '';

      const newImageData = helperCtx.createImageData(width, height);
      const dstData = newImageData.data;

      for (let i = 0; i < srcData.length; i += 4) {
        transformFn(srcData[i], srcData[i + 1], srcData[i + 2], srcData[i + 3], dstData, i);
      }

      helperCtx.putImageData(newImageData, 0, 0);
      return helperCanvas.toDataURL('image/png');
    };

    const previews: Record<string, string> = {};

    if (typeof document !== 'undefined') {
      // Standard channel modes
      previews.original = generateTransformedDataUrl((r, g, b, a, out, idx) => {
        out[idx] = r; out[idx + 1] = g; out[idx + 2] = b; out[idx + 3] = a;
      });
      previews.red = generateTransformedDataUrl((r, _, __, a, out, idx) => {
        out[idx] = r; out[idx + 1] = 0; out[idx + 2] = 0; out[idx + 3] = a;
      });
      previews.green = generateTransformedDataUrl((_, g, __, a, out, idx) => {
        out[idx] = 0; out[idx + 1] = g; out[idx + 2] = 0; out[idx + 3] = a;
      });
      previews.blue = generateTransformedDataUrl((_, __, b, a, out, idx) => {
        out[idx] = 0; out[idx + 1] = 0; out[idx + 2] = b; out[idx + 3] = a;
      });
      previews.inverse = generateTransformedDataUrl((r, g, b, a, out, idx) => {
        out[idx] = 255 - r; out[idx + 1] = 255 - g; out[idx + 2] = 255 - b; out[idx + 3] = a;
      });
      previews.lsb_half = generateTransformedDataUrl((r, g, b, a, out, idx) => {
        out[idx] = (r & 0x0F) << 4;
        out[idx + 1] = (g & 0x0F) << 4;
        out[idx + 2] = (b & 0x0F) << 4;
        out[idx + 3] = a;
      });

      // Pre-render all 8 bit planes for all 3 channels (R, G, B)
      const channels: ('red' | 'green' | 'blue')[] = ['red', 'green', 'blue'];
      for (const ch of channels) {
        for (let bit = 0; bit <= 7; bit++) {
          const key = `bitplane_${ch}_${bit}`;
          previews[key] = generateTransformedDataUrl((r, g, b, _, out, idx) => {
            let val = 0;
            if (ch === 'red') val = (r >> bit) & 1;
            else if (ch === 'green') val = (g >> bit) & 1;
            else if (ch === 'blue') val = (b >> bit) & 1;

            const intensity = val ? 255 : 0;
            out[idx] = intensity;
            out[idx + 1] = intensity;
            out[idx + 2] = intensity;
            out[idx + 3] = 255;
          });
        }
      }
    }

    context.onProgress?.(100, 'RGB analysis complete');

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
        dimensions: { width, height },
        channels: {
          red: redHist,
          green: greenHist,
          blue: blueHist
        },
        lsbDistribution: {
          red: rLsbRatio,
          green: gLsbRatio,
          blue: bLsbRatio
        },
        rgbaSamples,
        previews
      }
    };
  }
}
