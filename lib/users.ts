import { randomUUID, randomBytes, pbkdf2Sync, timingSafeEqual } from 'crypto';
import { z } from 'zod';

export interface PublicUser {
  id: string;
  name: string;
  email: string;
}

interface StoredUser extends PublicUser {
  passwordHash: string;
  salt: string;
}

const users: StoredUser[] = [];

export const userSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
  password: z.string().min(6),
});

function hashPassword(password: string, salt: string) {
  return pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
}

function sanitize(user: StoredUser): PublicUser {
  const { id, name, email } = user;
  return { id, name, email };
}

export function listUsers(): PublicUser[] {
  return users.map(sanitize);
}

export function createUser(data: z.infer<typeof userSchema>): PublicUser {
  const salt = randomBytes(16).toString('hex');
  const user: StoredUser = {
    id: randomUUID(),
    name: data.name,
    email: data.email,
    salt,
    passwordHash: hashPassword(data.password, salt),
  };
  users.push(user);
  return sanitize(user);
}

export function getUser(id: string): PublicUser | undefined {
  const user = users.find((u) => u.id === id);
  return user ? sanitize(user) : undefined;
}

export function updateUser(id: string, data: z.infer<typeof userSchema>): PublicUser | undefined {
  const user = users.find((u) => u.id === id);
  if (!user) return undefined;
  user.name = data.name;
  user.email = data.email;
  user.salt = randomBytes(16).toString('hex');
  user.passwordHash = hashPassword(data.password, user.salt);
  return sanitize(user);
}

export function deleteUser(id: string): boolean {
  const index = users.findIndex((u) => u.id === id);
  if (index === -1) return false;
  users.splice(index, 1);
  return true;
}

export function authenticate(email: string, password: string): PublicUser | null {
  const user = users.find((u) => u.email === email);
  if (!user) return null;
  const hash = hashPassword(password, user.salt);
  if (!timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.passwordHash, 'hex'))) {
    return null;
  }
  return sanitize(user);
}
