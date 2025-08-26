import { Tool, Scan, ScanResult, SummaryStats } from '../types';

export interface Provider {
  listScans(): Promise<Scan[]>;
  runTool(input: { tool: Tool; target: string; options?: Record<string, unknown> }): Promise<{ scanId: string }>;
  getScan(id: string): Promise<ScanResult>;
  getSummary(): Promise<SummaryStats>;
}
