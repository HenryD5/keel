import type { Logger } from './log';

/** Keel solo habla con estos hosts. Sin telemetría. */
export const ALLOWED_HOSTS: ReadonlySet<string> = new Set(['registry.npmjs.org', 'api.snyk.io', 'api.osv.dev', 'api.github.com']);

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
  ) {
    super(`HTTP ${status} for ${url}`);
    this.name = 'HttpError';
  }
}

export interface RequestOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export function assertAllowedUrl(url: string): URL {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname) || parsed.port !== '') {
    throw new Error(`Network access not allowed: ${parsed.origin}`);
  }
  return parsed;
}

export function createFetchJson(log: Logger, fetchImpl: typeof fetch = fetch) {
  return async function fetchJson(url: string, options: RequestOptions = {}): Promise<unknown> {
    const parsed = assertAllowedUrl(url);
    const { method = 'GET', headers = {}, body, timeoutMs = 30_000 } = options;
    const started = Date.now();
    const res = await fetchImpl(parsed, {
      method,
      headers: { Accept: 'application/json', 'User-Agent': 'keel-vscode', ...headers },
      body,
      // Una redirección podría llevar a un host fuera de la lista.
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    log.info(`${method} ${parsed.origin}${parsed.pathname} → ${res.status} (${Date.now() - started} ms)`);
    if (!res.ok) throw new HttpError(res.status, url);
    return res.json();
  };
}
