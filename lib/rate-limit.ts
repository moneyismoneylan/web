const requests = new Map<string, { count: number; start: number }>();

export function rateLimit(ip: string, limit = 30, windowMs = 60_000): boolean {
  const now = Date.now();
  const entry = requests.get(ip);
  if (!entry || now - entry.start > windowMs) {
    requests.set(ip, { count: 1, start: now });
    return true;
  }
  if (entry.count < limit) {
    entry.count += 1;
    return true;
  }
  return false;
}
