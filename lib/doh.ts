export async function dohResolve(name: string, type = 'A', signal?: AbortSignal) {
  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetch(url, { signal });
  if (!res.ok) throw new Error(`DoH ${res.status}`);
  return res.json() as Promise<{ Answer?: Array<{name:string; type:number; TTL:number; data:string}> }>;
}
