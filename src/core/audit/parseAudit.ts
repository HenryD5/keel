import type { Advisory, AuditEntry, AuditResult, RawAuditReport, RawVulnerability, Severity } from './types';
import { SEVERITY_ORDER } from './types';

export class AuditError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly detail?: string,
  ) {
    super(message);
    this.name = 'AuditError';
  }
}

/** Lee la salida de `npm audit --json`. Lanza `AuditError` si npm devolvió un error o el formato no es v2. */
export function parseAudit(stdout: string): AuditResult {
  let data: unknown;
  try {
    data = JSON.parse(stdout);
  } catch {
    throw new AuditError('EJSONPARSE', 'npm audit did not return valid JSON.');
  }
  if (!isObject(data)) throw new AuditError('EFORMAT', 'Unexpected npm audit output.');

  if (isObject(data.error)) {
    const err = data.error;
    throw new AuditError(
      typeof err.code === 'string' ? err.code : 'EAUDIT',
      typeof err.summary === 'string' ? err.summary : 'npm audit failed.',
      typeof err.detail === 'string' ? err.detail : undefined,
    );
  }
  if (data.auditReportVersion !== 2 || !isObject(data.vulnerabilities)) {
    throw new AuditError('EFORMAT', 'Unsupported npm audit report format (expected auditReportVersion 2).');
  }

  const report = data as unknown as RawAuditReport;
  const entries = new Map<string, AuditEntry>();
  for (const [name, raw] of Object.entries(report.vulnerabilities)) {
    entries.set(name, toEntry(name, raw));
  }
  return { entries, totals: report.metadata.vulnerabilities };
}

function toEntry(name: string, raw: RawVulnerability): AuditEntry {
  const advisories: Advisory[] = [];
  const viaPackages: string[] = [];
  const seen = new Set<number>();
  for (const via of raw.via) {
    if (typeof via === 'string') {
      viaPackages.push(via);
    } else if (!seen.has(via.source)) {
      seen.add(via.source);
      advisories.push({
        id: via.source,
        title: via.title,
        url: via.url,
        severity: via.severity,
        range: via.range,
        cwe: via.cwe ?? [],
      });
    }
  }
  return {
    name,
    severity: raw.severity,
    isDirect: raw.isDirect,
    advisories,
    viaPackages,
    effects: raw.effects,
    range: raw.range,
    nodes: raw.nodes,
    fixAvailable: raw.fixAvailable,
  };
}

export function maxSeverity(advisories: readonly { severity: Severity }[]): Severity | undefined {
  let max = -1;
  for (const a of advisories) max = Math.max(max, SEVERITY_ORDER.indexOf(a.severity));
  return max < 0 ? undefined : SEVERITY_ORDER[max];
}

export function countBySeverity(advisories: readonly { severity: Severity }[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const a of advisories) counts[a.severity]++;
  return counts;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
