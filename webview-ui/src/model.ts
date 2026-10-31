// Datos derivados del escaneo para las pantallas: categoría, versión destino, textos de cada fila.
import type { Severity } from '../../src/core/audit/types';
import type { PackageReport } from '../../src/core/scan';
import type { Lang, ScanPayload } from '../../src/webview/protocol';
import { formatDate, severityText, STRINGS } from './i18n';
import { category } from './filter';
import { defaultSelection } from '../../src/core/selection';

export { category, type Category } from './filter';

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'moderate', 'low', 'info'];

/** Versión hacia la que se actualizaría según la elección del dev (mínima por defecto). */
export function targetVersion(pkg: PackageReport, scan: ScanPayload): string | undefined {
  const r = pkg.resolution;
  if (!r) return undefined;
  if (scan.choices[pkg.name] === 'latest' && r.latest) return r.latest.version;
  return r.recommended?.version;
}

/** Versión que se analiza en el detalle: la recomendada o, si todas están en cuarentena, la que se espera. */
export function candidateVersion(pkg: PackageReport): string | undefined {
  return pkg.resolution?.recommended?.version ?? pkg.resolution?.waitingFor?.version;
}

export function isSelectable(pkg: PackageReport, scan: ScanPayload): boolean {
  return Boolean(targetVersion(pkg, scan)) && !isKept(pkg, scan);
}

export function isKept(pkg: PackageReport, scan: ScanPayload): boolean {
  return Boolean(scan.keep[pkg.name]);
}

/** Selección inicial del diseño: todo lo que tiene versión, salvo lo que la segunda fuente no confirma o se decidió mantener. */
/** Empiezan marcados los que se pueden aplicar, salvo si OSV/Snyk discrepa o el cambio es major: esos los decide el dev. */
export function defaultSelected(scan: ScanPayload): string[] {
  return defaultSelection(scan.result.packages, scan.keep);
}

export function vulnerabilityCount(pkg: PackageReport): number {
  return SEVERITIES.reduce((sum, s) => sum + pkg.counts[s], 0);
}

export function kindTag(lang: Lang, pkg: PackageReport): string {
  const t = STRINGS[lang];
  if (pkg.direct) return pkg.depType === 'dev' ? t.directDev : pkg.depType === 'optional' ? t.directOptional : t.direct;
  const via = pkg.viaTopLevel.length > 0 ? pkg.viaTopLevel : pkg.parents.map((p) => p.name || '—');
  return t.transitive(via.slice(0, 2).join(', ') + (via.length > 2 ? '…' : ''));
}

/** La "línea" de compatibilidad: `9` en 9.x; en 0.x el minor también rompe, así que `0.21`. */
export function majorOf(v: string): string {
  const [major, minor] = v.split('.');
  return major === '0' && minor !== undefined ? `0.${minor}` : (major ?? v);
}

/** Frase corta de la fila: qué corrige la versión y qué cambia. */
export function rowSummary(lang: Lang, pkg: PackageReport, scan: ScanPayload): string {
  const t = STRINGS[lang];
  if (pkg.error) return pkg.error;
  const keep = scan.keep[pkg.name];
  const r = pkg.resolution!;
  const parts: string[] = [];
  if (keep) parts.push(keep.version === pkg.installed ? t.kept(keep.reason) : t.keptStale(keep.version));

  if (r.status === 'quarantine-only' && r.waitingFor) {
    parts.push(t.quarantineOnly(r.waitingFor.version, formatDate(lang, r.waitingFor.waitUntil)));
    return parts.join(' ');
  }
  if (!r.recommended) {
    parts.push(t.noSafe);
    return parts.join(' ');
  }

  const rec = r.recommended;
  if (rec.bump === 'major' && !r.safeWithoutMajor) parts.push(t.onlyInMajor(majorOf(rec.version), pkg.declaredRange));
  else if (!pkg.direct && pkg.auditFix.kind === 'audit-fix' && pkg.parents[0]?.name) parts.push(t.parentAccepts(pkg.parents[0].name, rec.version));
  else parts.push(t.fixesAll(rec.version, vulnerabilityCount(pkg)));
  if (r.quarantineBypassed) parts.push(t.quarantineBypassed(rec.version));

  const c = pkg.checks;
  if (c) {
    if (c.newInstallScripts.length > 0) parts.push(t.newScripts(c.newInstallScripts.join(', ')));
    if (c.peerChanges.length > 0) parts.push(t.peerChanged(c.peerChanges.map((p) => p.name).join(', ')));
    if (c.engines.satisfiesProjectNode === false && c.engines.to) parts.push(t.nodeNotSatisfied(c.engines.to));
    else if (c.engines.from !== c.engines.to && c.engines.to) parts.push(t.nodeChanged(c.engines.to));
    if (c.newInstallScripts.length === 0 && c.peerChanges.length === 0 && c.engines.from === c.engines.to) parts.push(t.noPeerNoNode);
  }
  return parts.join(' ');
}

/** Nota bajo `actual → recomendada`: la última y por qué no se recomienda. */
export function versionNote(lang: Lang, pkg: PackageReport): string {
  const t = STRINGS[lang];
  const r = pkg.resolution;
  if (!r) return '';
  if (r.status === 'quarantine-only' && r.waitingFor) return t.waitUntil(formatDate(lang, r.waitingFor.waitUntil));
  if (r.recommended?.bump === 'major' && !r.safeWithoutMajor) return t.noSafeInMajor(majorOf(pkg.installed));
  const latest = r.latest;
  if (!latest || latest.reason === 'recommended') {
    if (!pkg.direct && pkg.parents[0]?.name && pkg.auditFix.kind === 'audit-fix') return t.withinParentRange(pkg.parents[0].name);
    return t.latestReason.recommended;
  }
  if (latest.reason === 'major-avoided') return `${t.latest(`${majorOf(latest.version)}.x`)} (${t.latestReason['major-avoided']})`;
  const age = latest.reason === 'quarantine' && latest.ageDays !== undefined ? `, ${t.publishedAgo(latest.ageDays)}` : '';
  return `${t.latest(latest.version)}${age} · ${t.latestReason[latest.reason]}`;
}

export function referenceCounts(lang: Lang, pkg: PackageReport): string {
  const issues = pkg.reference?.issues ?? [];
  const counts = new Map<Severity | undefined, number>();
  for (const i of issues) counts.set(i.severity, (counts.get(i.severity) ?? 0) + 1);
  const parts = SEVERITIES.filter((s) => counts.has(s)).map((s) => severityText(lang, s, counts.get(s)!));
  if (counts.has(undefined)) parts.push(STRINGS[lang].issues(counts.get(undefined)!));
  return parts.join(' · ');
}

export type RiskLevel = 'low' | 'medium' | 'high';

/** Veredicto del detalle: patch bajo, minor medio, major alto; cada señal de alarma sube un nivel. */
export function riskLevel(pkg: PackageReport): RiskLevel {
  const levels: RiskLevel[] = ['low', 'medium', 'high'];
  const r = pkg.resolution;
  const bump = r?.recommended?.bump ?? r?.waitingFor?.bump;
  let level = bump === 'patch' ? 0 : bump === 'minor' ? 1 : 2;
  const c = pkg.checks;
  const alarms = [
    pkg.reference?.agrees === false && !pkg.reference.error,
    (c?.newInstallScripts.length ?? 0) > 0,
    c?.peers.some((p) => p.satisfied === false && !p.optional),
    c?.engines.satisfiesProjectNode === false,
    r?.quarantineBypassed || r?.status !== 'ok',
  ].filter(Boolean).length;
  level = Math.min(2, level + alarms);
  return levels[level]!;
}
