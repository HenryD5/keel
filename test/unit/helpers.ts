import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Advisory, Severity } from '../../src/core/audit/types';
import type { Packument, VersionManifest } from '../../src/core/registry/types';

const FIXTURES = join(__dirname, '..', 'fixtures');

export function fixtureText(path: string): string {
  return readFileSync(join(FIXTURES, path), 'utf8');
}

export function packumentFixture(name: string): Packument {
  return JSON.parse(fixtureText(`registry/${name}.json`)) as Packument;
}

/** Fecha en la que se capturaron los fixtures reales (registro y npm audit). */
export const FIXTURE_NOW = new Date('2026-10-30T12:00:00Z');

export function daysAgo(days: number, now = FIXTURE_NOW): string {
  return new Date(now.getTime() - days * 24 * 60 * 60 * 1000).toISOString();
}

/** Packument sintético: `{ '1.0.0': { ageDays: 100 }, ... }`. */
export function makePackument(
  versions: Record<string, { ageDays?: number; deprecated?: string; manifest?: Partial<VersionManifest> }>,
  latest?: string,
): Packument {
  const doc: Packument = { name: 'pkg', 'dist-tags': {}, time: {}, versions: {} };
  for (const [v, opts] of Object.entries(versions)) {
    doc.versions[v] = { name: 'pkg', version: v, ...(opts.deprecated ? { deprecated: opts.deprecated } : {}), ...opts.manifest };
    if (opts.ageDays !== undefined) doc.time[v] = daysAgo(opts.ageDays);
  }
  doc['dist-tags'].latest = latest ?? Object.keys(versions).at(-1)!;
  return doc;
}

export function advisory(range: string, severity: Severity = 'high', id = Math.floor(Math.random() * 1e6)): Advisory {
  return { id, title: `Advisory ${id}`, url: `https://github.com/advisories/${id}`, severity, range, cwe: [] };
}
