import semver from 'semver';
import type { Advisory, Severity } from '../audit/types';
import type { Packument } from '../registry/types';
import type { ResolveResult } from './minSafeVersion';
import { ageInDays, isInQuarantine, vulnerabilityCounts } from './versions';

export type VersionRole = 'latest' | 'recommended' | 'waiting' | 'installed';

export interface VersionRow {
  version: string;
  counts: Record<Severity, number>;
  roles: VersionRole[];
  publishedAt?: string;
  inQuarantine: boolean;
  deprecated: boolean;
  malicious: boolean;
}

export interface VersionTableInput {
  packument: Packument;
  installed: string;
  advisories: readonly Advisory[];
  resolution: ResolveResult;
  excluded: ReadonlySet<string>;
  now: Date;
  quarantineDays: number;
}

/** Vecinas que se muestran alrededor de la instalada y de la recomendada. */
const NEIGHBORS = 2;

/**
 * Filas de "Versiones y vulnerabilidades", de la más nueva a la más vieja:
 * la última, la recomendada (o la que se espera), la instalada y unas pocas vecinas,
 * para ver dónde empiezan las versiones seguras sin listar todo el historial.
 */
export function buildVersionTable(input: VersionTableInput): VersionRow[] {
  const { packument, installed, advisories, resolution, excluded, now, quarantineDays } = input;
  const all = Object.keys(packument.versions)
    .filter((v) => semver.valid(v) && semver.prerelease(v) === null)
    .sort(semver.compare);

  const latest = resolution.latest?.version;
  const target = resolution.recommended?.version ?? resolution.waitingFor?.version;
  const pick = new Set<string>([installed]);
  if (latest) pick.add(latest);
  if (target) pick.add(target);

  const at = (v: string) => all.indexOf(v);
  const iInstalled = at(installed);
  if (iInstalled > 0) pick.add(all[iInstalled - 1]!);
  if (target) {
    const iTarget = at(target);
    // Las seguras justo encima de la recomendada y las vulnerables justo debajo.
    for (const v of all.slice(iTarget + 1, iTarget + 1 + NEIGHBORS)) pick.add(v);
    for (const v of all.slice(Math.max(iInstalled + 1, iTarget - NEIGHBORS), iTarget)) pick.add(v);
  } else if (iInstalled >= 0) {
    for (const v of all.slice(iInstalled + 1, iInstalled + 1 + NEIGHBORS)) pick.add(v);
  }

  return [...pick]
    .filter((v) => packument.versions[v] || v === installed)
    .sort(semver.rcompare)
    .map((version) => {
      const roles: VersionRole[] = [];
      if (version === latest) roles.push('latest');
      if (version === resolution.recommended?.version) roles.push('recommended');
      if (version === resolution.waitingFor?.version) roles.push('waiting');
      if (version === installed) roles.push('installed');
      const publishedAt = packument.time[version];
      return {
        version,
        counts: vulnerabilityCounts(version, advisories),
        roles,
        publishedAt,
        inQuarantine: isInQuarantine(ageInDays(publishedAt, now), quarantineDays),
        deprecated: Boolean(packument.versions[version]?.deprecated),
        malicious: excluded.has(version),
      };
    });
}
