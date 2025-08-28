import { exec } from 'child_process';
import { Provider } from './provider';
import { Scan, ScanResult, SummaryStats, Tool } from '../types';

/**
 * LiveProvider executes real command line tools to perform scans. It keeps
 * results in memory for the lifetime of the process. The intent is to provide
 * a simple demonstration implementation rather than a production ready
 * scanner.
 */
export class LiveProvider implements Provider {
  private scans: Scan[] = [];
  private results: Record<string, ScanResult> = {};
  private counter = 0;

  async listScans(): Promise<Scan[]> {
    return this.scans;
  }

  async runTool(input: {
    tool: Tool;
    target: string;
    options?: Record<string, unknown>;
  }): Promise<{ scanId: string }> {
    const id = String(++this.counter);
    const scan: Scan = {
      id,
      tool: input.tool,
      target: input.target,
      status: 'running',
      startedAt: new Date().toISOString(),
    };
    this.scans.push(scan);
    this.results[id] = { ...scan, finishedAt: '', output: {} };

    const cmd = this.commandFor(input.tool, input.target, input.options);
    exec(cmd, { timeout: 60_000, maxBuffer: 10_000_000 }, (err, stdout, stderr) => {
      const result = this.results[id];
      result.finishedAt = new Date().toISOString();
      result.output = {
        stdout: stdout.slice(0, 10_000),
        stderr: stderr.slice(0, 10_000),
      };
      if (err) {
        scan.status = 'failed';
        result.status = 'failed';
      } else {
        scan.status = 'completed';
        result.status = 'completed';
      }
    });

    return { scanId: id };
  }

  async getScan(id: string): Promise<ScanResult> {
    const res = this.results[id];
    if (!res) throw new Error('Scan not found');
    return res;
  }

  async getSummary(): Promise<SummaryStats> {
    const summary: SummaryStats = {
      total: this.scans.length,
      completed: 0,
      running: 0,
      failed: 0,
      byTool: { nmap: 0, sqlmap: 0, osint: 0, web: 0 },
    };
    for (const s of this.scans) {
      summary.byTool[s.tool] += 1;
      if (s.status === 'completed') summary.completed += 1;
      if (s.status === 'running') summary.running += 1;
      if (s.status === 'failed') summary.failed += 1;
    }
    return summary;
  }

  private commandFor(
    tool: Tool,
    target: string,
    _options?: Record<string, unknown>
  ): string {
    switch (tool) {
      case 'nmap':
        // -Pn treats targets as online even if they ignore ping probes
        return `nmap -Pn ${target}`;
      case 'sqlmap':
        // minimal flags for non-interactive runs
        return `sqlmap -u ${target} --batch --crawl=0 --level=1 --risk=1`;
      case 'osint':
        return `whois ${target}`;
      case 'web':
        // follow redirects and fetch headers
        return `curl -L -I ${target}`;
      default:
        return `echo unknown tool`;
    }
  }
}
