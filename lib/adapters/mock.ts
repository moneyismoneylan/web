import { Provider } from './provider';
import { Scan, ScanResult, SummaryStats, Tool } from '../types';
import scansData from '../../mocks/data/scans.json';
import scanResultsData from '../../mocks/data/scanResults.json';
import summaryData from '../../mocks/data/summary.json';

const scans: Scan[] = scansData as Scan[];
const scanResults: Record<string, ScanResult> = scanResultsData as Record<string, ScanResult>;
let summary: SummaryStats = summaryData as SummaryStats;

export class MockProvider implements Provider {
  async listScans(): Promise<Scan[]> {
    return scans;
  }

  async runTool(input: { tool: Tool; target: string; options?: Record<string, unknown> }): Promise<{ scanId: string }> {
    const id = String(scans.length + 1);
    const newScan: Scan = {
      id,
      tool: input.tool,
      target: input.target,
      status: 'running',
      startedAt: new Date().toISOString(),
    };
    scans.push(newScan);
    scanResults[id] = {
      ...newScan,
      finishedAt: '',
      output: {},
    };
    summary = {
      ...summary,
      total: summary.total + 1,
      running: summary.running + 1,
      byTool: { ...summary.byTool, [input.tool]: (summary.byTool[input.tool] || 0) + 1 },
    };
    return { scanId: id };
  }

  async getScan(id: string): Promise<ScanResult> {
    const result = scanResults[id];
    if (!result) throw new Error('Scan not found');
    return result;
  }

  async getSummary(): Promise<SummaryStats> {
    return summary;
  }
}
