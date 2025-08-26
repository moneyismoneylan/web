import { Provider } from './provider';
import { Scan, ScanResult, SummaryStats, Tool } from '../types';

export class LiveProvider implements Provider {
  async listScans(): Promise<Scan[]> {
    throw new Error('Live provider not implemented');
  }
  async runTool(_input: { tool: Tool; target: string; options?: Record<string, unknown> }): Promise<{ scanId: string }> {
    throw new Error('Live provider not implemented');
  }
  async getScan(_id: string): Promise<ScanResult> {
    throw new Error('Live provider not implemented');
  }
  async getSummary(): Promise<SummaryStats> {
    throw new Error('Live provider not implemented');
  }
}
