/**
 * The Hidden Bytes V2 - Analyzer Registry
 * Dynamic registration and lookup of all forensic and stego analyzers.
 */

import { Analyzer, FileDescriptor } from './types';

export class AnalyzerRegistry {
  private static instance: AnalyzerRegistry;
  private analyzers: Map<string, Analyzer> = new Map();

  private constructor() {}

  public static getInstance(): AnalyzerRegistry {
    if (!AnalyzerRegistry.instance) {
      AnalyzerRegistry.instance = new AnalyzerRegistry();
    }
    return AnalyzerRegistry.instance;
  }

  public register(analyzer: Analyzer): void {
    if (this.analyzers.has(analyzer.id)) {
      console.warn(`Analyzer with ID '${analyzer.id}' is already registered. Overwriting.`);
    }
    this.analyzers.set(analyzer.id, analyzer);
  }

  public unregister(id: string): boolean {
    return this.analyzers.delete(id);
  }

  public get(id: string): Analyzer | undefined {
    return this.analyzers.get(id);
  }

  public getAll(): Analyzer[] {
    return Array.from(this.analyzers.values());
  }

  public getApplicable(file: FileDescriptor): Analyzer[] {
    return this.getAll().filter(analyzer => analyzer.supports(file));
  }

  public clear(): void {
    this.analyzers.clear();
  }
}

export const registry = AnalyzerRegistry.getInstance();
