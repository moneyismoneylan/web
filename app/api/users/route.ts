import { NextResponse } from 'next/server';
import { listUsers, createUser, userSchema } from '@/lib/users';
import { rateLimit } from '@/lib/rate-limit';

export async function GET(request: Request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  return NextResponse.json(listUsers(), { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  try {
    const body = await request.json();
    const data = userSchema.parse(body);
    const user = createUser(data);
    return NextResponse.json(user, { headers: { 'Access-Control-Allow-Origin': '*' }, status: 201 });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid request';
    return NextResponse.json({ code: 'BAD_REQUEST', message }, { status: 400 });
  }
}

export function OPTIONS() {
  return NextResponse.json({}, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
