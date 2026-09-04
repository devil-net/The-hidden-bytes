/**
 * The Hidden Bytes V2 - Engine Barrel & Auto-Registration
 */

import { registry } from './registry';
import { RGBAnalyzer } from './analyzers/rgb';
import { StringsAnalyzer } from './analyzers/strings';
import { SignatureAnalyzer } from './analyzers/signatures';
import { EntropyAnalyzer } from './analyzers/entropy';
import { MetadataAnalyzer } from './analyzers/metadata';
import { BinwalkAnalyzer } from './analyzers/binwalk';
import { ZstegAnalyzer } from './analyzers/zsteg';
import { SteghideAnalyzer } from './analyzers/steghide';

// Auto-register core analyzers
export const rgbAnalyzer = new RGBAnalyzer();
export const stringsAnalyzer = new StringsAnalyzer();
export const signatureAnalyzer = new SignatureAnalyzer();
export const entropyAnalyzer = new EntropyAnalyzer();
export const metadataAnalyzer = new MetadataAnalyzer();
export const binwalkAnalyzer = new BinwalkAnalyzer();
export const zstegAnalyzer = new ZstegAnalyzer();
export const steghideAnalyzer = new SteghideAnalyzer();

registry.register(rgbAnalyzer);
registry.register(stringsAnalyzer);
registry.register(signatureAnalyzer);
registry.register(entropyAnalyzer);
registry.register(metadataAnalyzer);
registry.register(binwalkAnalyzer);
registry.register(zstegAnalyzer);
registry.register(steghideAnalyzer);

export * from './types';
export * from './errors';
export * from './registry';
export * from './scheduler';
export * from './manager';
export * from './correlator';
export * from './vfs';
