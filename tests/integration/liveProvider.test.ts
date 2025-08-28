import { describe, it, expect } from 'vitest';
import { LiveProvider } from '@/lib/adapters/live';

describe('LiveProvider', () => {
  it('executes web scan via curl', async () => {
    const provider = new LiveProvider();
    const { scanId } = await provider.runTool({ tool: 'web', target: 'https://example.com' });
    await new Promise((r) => setTimeout(r, 1000));
    const result = await provider.getScan(scanId);
    expect(result.output.stdout).toContain('HTTP/');
    expect(result.status).toBe('completed');
    const summary = await provider.getSummary();
    expect(summary.total).toBe(1);
  }, 20000);
});
