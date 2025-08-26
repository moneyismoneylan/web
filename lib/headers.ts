export interface HeaderFinding {
  header: string;
  ok: boolean;
  message: string;
}

export function parseRawHeaders(raw: string): Record<string, string> {
  const map: Record<string, string> = {};
  raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .forEach((line) => {
      const idx = line.indexOf(':');
      if (idx > -1) {
        const key = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        map[key] = value;
      }
    });
  return map;
}

interface Rule {
  header: string;
  weight: number;
  check: (value: string) => boolean;
  msg: string;
}

const rules: Rule[] = [
  {
    header: 'strict-transport-security',
    weight: 20,
    check: (v) => /max-age/i.test(v),
    msg: 'Missing or invalid HSTS header',
  },
  {
    header: 'content-security-policy',
    weight: 25,
    check: (v) => !/unsafe-inline|unsafe-eval/gi.test(v),
    msg: 'CSP missing or allows unsafe inline/eval',
  },
  {
    header: 'x-frame-options',
    weight: 10,
    check: (v) => ['deny', 'sameorigin'].includes(v.toLowerCase()),
    msg: 'X-Frame-Options should be DENY or SAMEORIGIN',
  },
  {
    header: 'x-content-type-options',
    weight: 10,
    check: (v) => v.toLowerCase() === 'nosniff',
    msg: 'X-Content-Type-Options should be nosniff',
  },
  {
    header: 'referrer-policy',
    weight: 10,
    check: (v) => v.length > 0,
    msg: 'Referrer-Policy missing',
  },
  {
    header: 'permissions-policy',
    weight: 15,
    check: (v) => v.length > 0,
    msg: 'Permissions-Policy missing',
  },
  {
    header: 'cache-control',
    weight: 10,
    check: (v) => /no-store|no-cache/i.test(v),
    msg: 'Cache-Control missing or not restrictive',
  },
];

export function auditHeaders(raw: string) {
  const map = parseRawHeaders(raw);
  let score = 0;
  const findings: HeaderFinding[] = [];
  for (const rule of rules) {
    const val = map[rule.header];
    const ok = val ? rule.check(val) : false;
    if (ok) score += rule.weight;
    findings.push({ header: rule.header, ok, message: ok ? 'ok' : rule.msg });
  }
  return { score, findings };
}
