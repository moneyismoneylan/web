import { NextResponse } from 'next/server';
import { getProvider } from '@/lib/adapters';
import { rateLimit } from '@/lib/rate-limit';

export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  const provider = getProvider();
  const summary = await provider.getSummary();
  return NextResponse.json(summary, { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export function OPTIONS() {
  return NextResponse.json({}, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
