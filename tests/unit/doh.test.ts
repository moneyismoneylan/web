import { dohResolve } from '../../lib/doh';

describe('dohResolve', () => {
  it('fetches DNS records', async () => {
    const mock = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ Answer: [] }),
    } as any);
    // @ts-ignore
    global.fetch = mock;
    const result = await dohResolve('example.com', 'A');
    expect(mock).toHaveBeenCalledWith(
      'https://dns.google/resolve?name=example.com&type=A',
      { signal: undefined }
    );
    expect(result).toEqual({ Answer: [] });
  });
});
