'use client';
import { useState } from 'react';
import { auditHeaders } from '@/lib/headers';
import { ResultCard } from '@/components/tools/ResultCard';

export default function HeadersTool() {
  const [raw, setRaw] = useState('');
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState<string | undefined>();

  function run() {
    try {
      setErr(undefined);
      const res = auditHeaders(raw);
      setResult(res);
    } catch (e: any) {
      setErr(e.message);
    }
  }

  return (
    <div className="space-y-4">
      <textarea
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        placeholder="Strict-Transport-Security: max-age=63072000\nContent-Security-Policy: default-src 'self'"
        className="w-full h-40 p-2 bg-gray-900 text-gray-100 rounded"
      />
      <button onClick={run} className="px-4 py-2 bg-blue-600 text-white rounded">Audit</button>
      <ResultCard data={result} error={err} />
    </div>
  );
}
