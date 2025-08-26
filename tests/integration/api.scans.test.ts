// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { GET as listScans, POST as runScan } from '@/app/api/scans/route';
import { GET as getScan } from '@/app/api/scans/[id]/route';
import { GET as getSummary } from '@/app/api/summary/route';

describe('scans API', () => {
  it('lists scans', async () => {
    const res = await listScans();
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it('starts scan and retrieves it', async () => {
    const res = await runScan(
      new Request('http://localhost/api/scans', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ tool: 'nmap', target: 'example.com' }),
      })
    );
    expect(res.ok).toBe(true);
    const { scanId } = await res.json();
    const res2 = await getScan(new Request('http://localhost'), { params: { id: scanId } });
    const data = await res2.json();
    expect(data.id).toBe(scanId);
  });

  it('gets summary', async () => {
    const res = await getSummary(new Request('http://localhost'));
    const data = await res.json();
    expect(data.total).toBeGreaterThan(0);
  });
});
