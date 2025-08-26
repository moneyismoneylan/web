import { NextResponse } from 'next/server';
import { z } from 'zod';
import { getProvider } from '@/lib/adapters';
import { rateLimit } from '@/lib/rate-limit';
import { Tool } from '@/lib/types';

const runSchema = z.object({
  tool: z.enum(['nmap', 'sqlmap', 'osint', 'web']),
  target: z.string().min(1),
  options: z.record(z.any()).optional(),
});

export async function GET() {
  const provider = getProvider();
  const scans = await provider.listScans();
  return NextResponse.json(scans, { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  try {
    const body = await request.json();
    const input = runSchema.parse(body);
    const provider = getProvider();
    const result = await provider.runTool(input as { tool: Tool; target: string; options?: Record<string, unknown> });
    return NextResponse.json(result, { headers: { 'Access-Control-Allow-Origin': '*' } });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid request';
    return NextResponse.json({ code: 'BAD_REQUEST', message }, { status: 400 });
  }
}

export function OPTIONS() {
  return NextResponse.json({}, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
