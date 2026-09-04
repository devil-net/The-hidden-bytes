/**
 * The Hidden Bytes V2 - Multi-Layer Steganography Passphrase & Hint Decoder
 * Recursively decodes Base64, Hex, and URL encodings from comments, text chunks, and metadata.
 * Detects targets like steghide, outguess, and flags.
 */

export interface DecodedStegoHint {
  sourceField: string;
  originalValue: string;
  decodedLayers: string[];
  finalDecodedText: string;
  targetTool?: 'steghide' | 'outguess' | 'openstego' | 'generic';
  candidatePassphrase?: string;
  isFlag: boolean;
  confidence: 'high' | 'medium' | 'low';
}

function isValidBase64(str: string): boolean {
  const clean = str.trim();
  if (clean.length < 4 || clean.length % 4 !== 0 && !clean.includes('=')) {
    // If unpadded, check if length % 4 is valid when padded
    if (clean.length % 4 === 1) return false;
  }
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(clean)) {
    return false;
  }
  try {
    const decoded = atob(clean.replace(/-/g, '+').replace(/_/g, '/'));
    // Check if decoded contains mostly printable characters
    let printable = 0;
    for (let i = 0; i < decoded.length; i++) {
      const code = decoded.charCodeAt(i);
      if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
        printable++;
      }
    }
    return printable / decoded.length >= 0.75;
  } catch {
    return false;
  }
}

function decodeBase64Safe(str: string): string | null {
  try {
    let clean = str.trim().replace(/-/g, '+').replace(/_/g, '/');
    while (clean.length % 4 !== 0) {
      clean += '=';
    }
    const decoded = atob(clean);
    return decoded;
  } catch {
    return null;
  }
}

function isValidHex(str: string): boolean {
  const clean = str.trim();
  if (clean.length < 6 || clean.length % 2 !== 0) return false;
  if (!/^[0-9a-fA-F]+$/.test(clean)) return false;

  try {
    let printable = 0;
    const len = clean.length / 2;
    for (let i = 0; i < clean.length; i += 2) {
      const code = parseInt(clean.substring(i, i + 2), 16);
      if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
        printable++;
      }
    }
    return printable / len >= 0.75;
  } catch {
    return false;
  }
}

function decodeHexSafe(str: string): string | null {
  try {
    const clean = str.trim();
    let res = '';
    for (let i = 0; i < clean.length; i += 2) {
      res += String.fromCharCode(parseInt(clean.substring(i, i + 2), 16));
    }
    return res;
  } catch {
    return null;
  }
}

export function analyzeStegoHints(sourceField: string, value: string): DecodedStegoHint | null {
  if (!value || typeof value !== 'string') return null;
  const originalTrimmed = value.trim();
  if (originalTrimmed.length < 3) return null;

  const decodedLayers: string[] = [originalTrimmed];
  let current = originalTrimmed;
  let maxLayers = 3;

  while (maxLayers > 0) {
    let nextLayer: string | null = null;

    // Test Base64
    if (isValidBase64(current)) {
      const b64 = decodeBase64Safe(current);
      if (b64 && b64 !== current) {
        nextLayer = b64;
      }
    }

    // Test Hex
    if (!nextLayer && isValidHex(current)) {
      const hex = decodeHexSafe(current);
      if (hex && hex !== current) {
        nextLayer = hex;
      }
    }

    // Test URL encoding
    if (!nextLayer && current.includes('%') && /%[0-9a-fA-F]{2}/.test(current)) {
      try {
        const urlDecoded = decodeURIComponent(current);
        if (urlDecoded !== current) {
          nextLayer = urlDecoded;
        }
      } catch {
        // Ignored
      }
    }

    if (nextLayer) {
      decodedLayers.push(nextLayer);
      current = nextLayer;
      maxLayers--;
    } else {
      break;
    }
  }

  // Check if any layer or original string has steganography keywords or structure
  const allTexts = [...decodedLayers];
  let targetTool: 'steghide' | 'outguess' | 'openstego' | 'generic' | undefined;
  let candidatePassphrase: string | undefined;
  let isFlag = false;

  for (const text of allTexts) {
    const lower = text.toLowerCase();

    if (lower.includes('flag{') || lower.includes('ctf{') || lower.includes('htb{')) {
      isFlag = true;
    }

    // Pattern: steghide:<pass> or steghide: <pass>
    const steghideMatch = /steghide\s*[:=\-]\s*([^\s\r\n]+)/i.exec(text);
    if (steghideMatch) {
      targetTool = 'steghide';
      let pass = steghideMatch[1].trim();
      // If the password part itself is base64, decode it!
      if (isValidBase64(pass)) {
        const decPass = decodeBase64Safe(pass);
        if (decPass) {
          decodedLayers.push(`steghide:${decPass}`);
          pass = decPass;
        }
      }
      candidatePassphrase = pass;
      break;
    }

    // Pattern: outguess:<pass>
    const outguessMatch = /outguess\s*[:=\-]\s*([^\s\r\n]+)/i.exec(text);
    if (outguessMatch) {
      targetTool = 'outguess';
      candidatePassphrase = outguessMatch[1].trim();
      break;
    }

    // Pattern: pass/password/key:<pass>
    const passMatch = /(?:password|pass|key|secret)\s*[:=\-]\s*([^\s\r\n]+)/i.exec(text);
    if (passMatch) {
      targetTool = 'generic';
      let pass = passMatch[1].trim();
      if (isValidBase64(pass)) {
        const decPass = decodeBase64Safe(pass);
        if (decPass) {
          pass = decPass;
        }
      }
      candidatePassphrase = pass;
      break;
    }
  }

  // If decoded deeper than original or matched stego pattern
  if (decodedLayers.length > 1 || candidatePassphrase || isFlag || targetTool) {
    const finalDecoded = decodedLayers[decodedLayers.length - 1];
    return {
      sourceField,
      originalValue: originalTrimmed,
      decodedLayers,
      finalDecodedText: finalDecoded,
      targetTool,
      candidatePassphrase: candidatePassphrase || (decodedLayers.length > 1 ? finalDecoded : undefined),
      isFlag,
      confidence: candidatePassphrase || isFlag ? 'high' : 'medium'
    };
  }

  return null;
}
