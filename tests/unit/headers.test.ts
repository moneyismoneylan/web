import { describe, it, expect } from 'vitest';
import { auditHeaders } from '@/lib/headers';

describe('header auditor', () => {
  it('scores full headers as 100', () => {
    const raw = `Strict-Transport-Security: max-age=63072000\nContent-Security-Policy: default-src 'self'\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nReferrer-Policy: no-referrer\nPermissions-Policy: camera=()\nCache-Control: no-store`;
    const res = auditHeaders(raw);
    expect(res.score).toBe(100);
  });

  it('scores missing headers as low', () => {
    const res = auditHeaders('Server: nginx');
    expect(res.score).toBe(0);
  });
});
