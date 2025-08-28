// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { POST as createUser } from '@/app/api/users/route';
import { POST as login } from '@/app/api/auth/login/route';

describe('users API', () => {
  it('registers and logs in user', async () => {
    const res = await createUser(
      new Request('http://localhost/api/users', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Alice', email: 'alice@example.com', password: 'secret123' }),
      })
    );
    expect(res.status).toBe(201);
    const created = await res.json();
    expect(created.email).toBe('alice@example.com');

    const loginRes = await login(
      new Request('http://localhost/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'alice@example.com', password: 'secret123' }),
      })
    );
    expect(loginRes.ok).toBe(true);
    const data = await loginRes.json();
    expect(data.user.email).toBe('alice@example.com');
    expect(typeof data.token).toBe('string');
  });

  it('rejects invalid login', async () => {
    const res = await login(
      new Request('http://localhost/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'wrong@example.com', password: 'nope' }),
      })
    );
    expect(res.status).toBe(401);
  });
});
