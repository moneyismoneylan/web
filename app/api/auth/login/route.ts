import { NextResponse } from 'next/server';
import { authenticate } from '@/lib/users';
import { signToken } from '@/lib/auth';
import { rateLimit } from '@/lib/rate-limit';

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  try {
    const body = await request.json();
    const { email, password } = body as { email?: string; password?: string };
    if (!email || !password) {
      return NextResponse.json({ code: 'BAD_REQUEST', message: 'Email and password required' }, { status: 400 });
    }
    const user = authenticate(email, password);
    if (!user) {
      return NextResponse.json({ code: 'UNAUTHORIZED', message: 'Invalid credentials' }, { status: 401 });
    }
    const token = signToken({ sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) + 60 * 60 });
    return NextResponse.json({ token, user }, { headers: { 'Access-Control-Allow-Origin': '*' } });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid request';
    return NextResponse.json({ code: 'BAD_REQUEST', message }, { status: 400 });
  }
}

export function OPTIONS() {
  return NextResponse.json(
    {},
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    }
  );
}
