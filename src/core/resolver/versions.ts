import semver from 'semver';
import type { Advisory, Severity } from '../audit/types';
import { countBySeverity } from '../audit/parseAudit';

export type Bump = 'patch' | 'minor' | 'major';

/**
 * Tipo de salto entre dos versiones según lo que acepta un rango con `^`.
 * En 0.x un cambio de minor (o de patch en 0.0.x) también rompe, así que cuenta como major.
 */
export function bumpType(from: string, to: string): Bump {
  const a = semver.parse(from);
  const b = semver.parse(to);
  if (!a || !b) throw new Error(`Invalid versions: ${from}, ${to}`);
  if (a.major !== b.major) return 'major';
  if (a.major === 0 && a.minor !== b.minor) return 'major';
  if (a.major === 0 && a.minor === 0 && a.patch !== b.patch) return 'major';
  if (a.minor !== b.minor) return 'minor';
  return 'patch';
}

/**
 * Advisories que afectan a `version`. Un rango que semver no entiende se trata
 * como si afectara a todas las versiones: es preferible no recomendar nada a recomendar mal.
 */
export function advisoriesFor(version: string, advisories: readonly Advisory[]): Advisory[] {
  return advisories.filter((a) => {
    if (semver.validRange(a.range) === null) return true;
    return semver.satisfies(version, a.range);
  });
}

export function isVulnerable(version: string, advisories: readonly Advisory[]): boolean {
  return advisoriesFor(version, advisories).length > 0;
}

export function vulnerabilityCounts(version: string, advisories: readonly Advisory[]): Record<Severity, number> {
  return countBySeverity(advisoriesFor(version, advisories));
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function ageInDays(publishedAt: string | undefined, now: Date): number | undefined {
  if (!publishedAt) return undefined;
  const t = Date.parse(publishedAt);
  if (Number.isNaN(t)) return undefined;
  return (now.getTime() - t) / DAY_MS;
}

/** Una versión sin fecha conocida se considera en cuarentena. */
export function isInQuarantine(ageDays: number | undefined, quarantineDays: number): boolean {
  if (quarantineDays <= 0) return false;
  return ageDays === undefined || ageDays < quarantineDays;
}
