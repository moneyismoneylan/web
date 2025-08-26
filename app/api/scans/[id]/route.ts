import { NextResponse } from 'next/server';
import { getProvider } from '@/lib/adapters';
import { rateLimit } from '@/lib/rate-limit';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  try {
    const provider = getProvider();
    const result = await provider.getScan(params.id);
    return NextResponse.json(result, { headers: { 'Access-Control-Allow-Origin': '*' } });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Not found';
    return NextResponse.json({ code: 'NOT_FOUND', message }, { status: 404 });
  }
}

export function OPTIONS() {
  return NextResponse.json({}, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
