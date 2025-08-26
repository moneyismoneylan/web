export type Tool = 'nmap' | 'sqlmap' | 'osint' | 'web';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed';

export interface Scan {
  id: string;
  tool: Tool;
  target: string;
  status: ScanStatus;
  startedAt: string;
}

export interface ScanResult extends Scan {
  finishedAt: string;
  output: Record<string, unknown>;
}

export interface SummaryStats {
  total: number;
  completed: number;
  running: number;
  failed: number;
  byTool: Record<Tool, number>;
}
