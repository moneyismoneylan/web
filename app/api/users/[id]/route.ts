import { NextResponse } from 'next/server';
import { getUser, updateUser, deleteUser, userSchema } from '@/lib/users';
import { rateLimit } from '@/lib/rate-limit';

export async function GET(request: Request, { params }: { params: { id: string } }) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  const user = getUser(params.id);
  if (!user) {
    return NextResponse.json({ code: 'NOT_FOUND', message: 'User not found' }, { status: 404 });
  }
  return NextResponse.json(user, { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export async function PUT(request: Request, { params }: { params: { id: string } }) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  try {
    const body = await request.json();
    const data = userSchema.parse(body);
    const user = updateUser(params.id, data);
    if (!user) {
      return NextResponse.json({ code: 'NOT_FOUND', message: 'User not found' }, { status: 404 });
    }
    return NextResponse.json(user, { headers: { 'Access-Control-Allow-Origin': '*' } });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid request';
    return NextResponse.json({ code: 'BAD_REQUEST', message }, { status: 400 });
  }
}

export async function DELETE(request: Request, { params }: { params: { id: string } }) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';
  if (!rateLimit(ip)) {
    return NextResponse.json({ code: 'RATE_LIMIT', message: 'Too many requests' }, { status: 429 });
  }
  const removed = deleteUser(params.id);
  if (!removed) {
    return NextResponse.json({ code: 'NOT_FOUND', message: 'User not found' }, { status: 404 });
  }
  return NextResponse.json({ success: true }, { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export function OPTIONS() {
  return NextResponse.json({}, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,PUT,DELETE,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
}
