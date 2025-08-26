'use client';
import { useState } from 'react';
import { dohResolve } from '@/lib/doh';
import { ResultCard } from '@/components/tools/ResultCard';

export default function DnsTool() {
  const [domain, setDomain] = useState('');
  const [type, setType] = useState<'A'|'AAAA'|'CNAME'|'MX'|'TXT'|'NS'>('A');
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState<string|undefined>();

  async function run() {
    setErr(undefined);
    try { setResult(await dohResolve(domain, type)); }
    catch (e:any) { setErr(e.message); }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" className="border px-2 py-1 rounded text-black" />
        <select value={type} onChange={e=>setType(e.target.value as any)} className="border px-2 py-1 rounded text-black">
          {['A','AAAA','CNAME','MX','TXT','NS'].map(t=><option key={t}>{t}</option>)}
        </select>
        <button onClick={run} className="bg-blue-600 text-white px-3 py-1 rounded">Resolve</button>
      </div>
      <ResultCard data={result} error={err} />
    </div>
  );
}
