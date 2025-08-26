import { dohResolve } from '@/lib/doh';
import { auditHeaders } from '@/lib/headers';
import type { ToolDefinition } from './types';

export const categories = ['Recon','Web','Crypto','Forensics','OSINT','Utils'] as const;

export const tools: ToolDefinition[] = [
  {
    meta: {
      id: 'dns',
      name: 'DNS Resolver',
      category: 'Recon',
      description: 'Resolve DNS records using public DoH',
      offline: false,
      inputs: [
        { key: 'domain', label: 'Domain', type: 'text', required: true },
        {
          key: 'type',
          label: 'Type',
          type: 'select',
          options: ['A','AAAA','CNAME','MX','TXT','NS'].map((t) => ({ label: t, value: t })),
          required: true,
        },
      ],
    },
    run: async (input) => {
      const { domain, type } = input as { domain: string; type: string };
      const data = await dohResolve(domain, type);
      return { ok: true, data };
    },
  },
  {
    meta: {
      id: 'headers',
      name: 'Security Headers Auditor',
      category: 'Web',
      description: 'Score common HTTP security headers',
      offline: true,
      inputs: [
        { key: 'raw', label: 'Headers', type: 'textarea', required: true },
      ],
    },
    run: async (input) => {
      const { raw } = input as { raw: string };
      const res = auditHeaders(raw);
      return {
        ok: true,
        data: res,
        score: res.score,
        insights: res.findings.map((f) => ({
          label: f.header,
          value: f.message,
          severity: f.ok ? 'info' : 'warn',
        })),
      };
    },
  },
];
