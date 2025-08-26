import { Provider } from './provider';
import { MockProvider } from './mock';
import { LiveProvider } from './live';

export function getProvider(): Provider {
  if (process.env.USE_MOCKS !== 'false') {
    return new MockProvider();
  }
  return new LiveProvider();
}
