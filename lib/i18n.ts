import en from '../locales/en/common.json';
import tr from '../locales/tr/common.json';

const dictionaries = { en, tr } as const;

export type Locale = keyof typeof dictionaries;

export function getDictionary(locale: Locale) {
  return dictionaries[locale];
}
