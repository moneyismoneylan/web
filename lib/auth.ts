import { createHmac } from 'crypto';

const SECRET = process.env.JWT_SECRET || 'dev-secret';

function base64url(input: Buffer | string) {
  return Buffer.from(input).toString('base64url');
}

export interface TokenPayload {
  sub: string;
  email: string;
  exp: number;
}

export function signToken(payload: TokenPayload): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', SECRET).update(data).digest('base64url');
  return `${data}.${signature}`;
}

export function verifyToken(token: string): TokenPayload | null {
  const [header, payload, signature] = token.split('.');
  if (!header || !payload || !signature) return null;
  const data = `${header}.${payload}`;
  const expected = createHmac('sha256', SECRET).update(data).digest('base64url');
  if (signature !== expected) return null;
  const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as TokenPayload;
  if (parsed.exp < Math.floor(Date.now() / 1000)) return null;
  return parsed;
}
