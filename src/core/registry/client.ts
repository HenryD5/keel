import { assertPackageName } from '../validate';
import type { Packument } from './types';

export const REGISTRY_ORIGIN = 'https://registry.npmjs.org';

export type FetchJson = (url: string) => Promise<unknown>;

/** `@scope/name` → `https://registry.npmjs.org/@scope%2Fname`. */
export function packumentUrl(name: string): string {
  assertPackageName(name);
  const path = name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  return `${REGISTRY_ORIGIN}/${path}`;
}

/** Cliente del registro con caché en memoria por instancia (una por escaneo). */
export class RegistryClient {
  private readonly cache = new Map<string, Promise<Packument>>();

  constructor(private readonly fetchJson: FetchJson) {}

  getPackument(name: string): Promise<Packument> {
    let pending = this.cache.get(name);
    if (!pending) {
      pending = this.fetchJson(packumentUrl(name)).then((data) => toPackument(name, data));
      // Si falla, no se guarda: el siguiente intento vuelve a pedirlo.
      pending.catch(() => this.cache.delete(name));
      this.cache.set(name, pending);
    }
    return pending;
  }
}

function toPackument(name: string, data: unknown): Packument {
  const doc = data as Partial<Packument> | null;
  if (!doc || typeof doc !== 'object' || typeof doc.versions !== 'object' || doc.versions === null) {
    throw new Error(`Unexpected registry response for ${name}.`);
  }
  return {
    name: doc.name ?? name,
    'dist-tags': doc['dist-tags'] ?? {},
    repository: doc.repository,
    time: doc.time ?? {},
    versions: doc.versions,
  };
}
