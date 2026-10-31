// Resumen en texto del escaneo para el Output Channel. La interfaz definitiva es el webview (Fase 2).
import type { Severity } from './audit/types';
import type { PackageReport, ScanResult } from './scan';
import type { LatestReason } from './resolver/minSafeVersion';
import type { Bump } from './resolver/versions';

export interface ApplyReportInput {
  language: 'es' | 'en';
  before?: Record<string, number>;
  after?: Record<string, number>;
  updated?: Array<{ name: string; from: string; to: string }>;
  removed?: string[];
  pending?: Array<{ name: string; reason: string }>;
  validation?: Array<{ script: string; status: 'passed' | 'skipped' | 'failed'; detail?: string }>;
  registryWarnings?: Array<{ package: string; host: string; reason: string }>;
  versionWarnings?: Array<{ name: string; planned: string; installed?: string }>;
  failedStep?: { name: string; reason: string };
}

/** Informe Markdown para portapapeles y PR; no infiere éxito de pasos omitidos. */
export function buildApplyReport(input: ApplyReportInput): string {
  const es = input.language === 'es';
  const lines = [`# ${es ? 'Informe de seguridad de dependencias' : 'Dependency security report'}`];
  const section = (title: string, rows: string[]) => { if (rows.length) lines.push('', `## ${title}`, '', ...rows); };
  if (input.before) section(es ? 'Vulnerabilidades antes' : 'Vulnerabilities before', countRows(input.before));
  if (input.after) section(es ? 'Vulnerabilidades después' : 'Vulnerabilities after', countRows(input.after));
  section(es ? 'Paquetes actualizados' : 'Updated packages', (input.updated ?? []).map((x) => `- **${x.name}**: ${x.from} → ${x.to}`));
  section(es ? 'Paquetes eliminados' : 'Removed packages', (input.removed ?? []).map((x) => `- **${x}**`));
  section(es ? 'Paso fallido' : 'Failed step', input.failedStep ? [`- **${input.failedStep.name}**: ${input.failedStep.reason}`] : []);
  section(es ? 'Vulnerabilidades pendientes' : 'Pending vulnerabilities', (input.pending ?? []).map((x) => `- **${x.name}**: ${x.reason}`));
  section(es ? 'Validación' : 'Validation', (input.validation ?? []).map((x) => `- **npm run ${x.script}**: ${validationLabel(x.status, es)}${x.detail ? ` — ${x.detail}` : ''}`));
  section(es ? 'Avisos de registro' : 'Registry warnings', (input.registryWarnings ?? []).map((x) => `- **${x.package}**: ${x.host} (${x.reason})`));
  section(es ? 'Avisos de versión instalada' : 'Installed version warnings', (input.versionWarnings ?? []).map((x) => `- **${x.name}**: ${es ? 'planificada' : 'planned'} ${x.planned}, ${es ? 'instalada' : 'installed'} ${x.installed ?? (es ? 'no encontrada' : 'not found')}`));
  const unresolved = (input.pending?.length ?? 0) + (input.failedStep ? 1 : 0) + (input.validation?.filter((x) => x.status !== 'passed').length ?? 0) + (input.registryWarnings?.length ?? 0) + (input.versionWarnings?.length ?? 0);
  lines.push('', unresolved ? (es ? `**Quedan ${unresolved} elemento(s) sin resolver o verificar.**` : `**${unresolved} item(s) remain unresolved or unverified.**`) : (es ? '**No quedan elementos sin resolver en este informe.**' : '**No unresolved items remain in this report.**'));
  return `${lines.join('\n')}\n`;
}

function countRows(counts: Record<string, number>): string[] {
  return Object.entries(counts).filter(([, n]) => n > 0).map(([name, n]) => `- ${name}: ${n}`).concat(Object.values(counts).every((n) => n === 0) ? ['- 0'] : []);
}

function validationLabel(status: 'passed' | 'skipped' | 'failed', es: boolean): string {
  return es ? ({ passed: 'aprobado', skipped: 'omitido', failed: 'falló' } as const)[status] : status;
}

const SEVERITY_LABEL: Record<Severity, [one: string, many: string]> = {
  critical: ['crítica', 'críticas'],
  high: ['alta', 'altas'],
  moderate: ['media', 'medias'],
  low: ['baja', 'bajas'],
  info: ['informativa', 'informativas'],
};

const BUMP_LABEL: Record<Bump, string> = {
  patch: 'Patch · Seguro',
  minor: 'Minor · Revisar',
  major: 'Major · Puede romper',
};

const LATEST_REASON: Record<LatestReason, string> = {
  recommended: 'es la recomendada',
  'not-newer': 'no es mayor que la instalada',
  vulnerable: 'también es vulnerable',
  deprecated: 'está deprecated',
  excluded: 'descartada por otra fuente',
  quarantine: 'en cuarentena',
  'major-avoided': 'major, se evita',
  'not-needed': 'una anterior ya corrige todo',
};

export function formatSeverityCounts(counts: Record<Severity, number>): string {
  const parts: string[] = [];
  for (const s of ['critical', 'high', 'moderate', 'low', 'info'] as const) {
    const n = counts[s];
    if (n > 0) parts.push(`${n} ${SEVERITY_LABEL[s][n === 1 ? 0 : 1]}`);
  }
  return parts.join(' · ') || 'sin vulnerabilidades';
}

export function formatScanReport(result: ScanResult, quarantineDays: number): string {
  const lines: string[] = [];
  const t = result.totals;
  lines.push(`${result.projectName ?? 'Proyecto'} · ${result.packages.length} paquetes con vulnerabilidades propias`);
  lines.push(`Total npm audit: ${formatSeverityCounts({ critical: t.critical, high: t.high, moderate: t.moderate, low: t.low, info: t.info })}`);
  lines.push('');
  for (const pkg of result.packages) lines.push(...formatPackage(pkg, quarantineDays), '');
  if (result.inheritedOnly.length > 0) {
    lines.push(`Afectados solo por sus dependencias (se corrigen al corregir estas): ${result.inheritedOnly.join(', ')}`);
  }
  return lines.join('\n');
}

function formatPackage(pkg: PackageReport, quarantineDays: number): string[] {
  const kind = pkg.direct
    ? `directa${pkg.depType === 'dev' ? ' · dev' : ''} · ${pkg.declaredRange}`
    : `transitiva · vía ${pkg.viaTopLevel.join(', ') || pkg.parents.map((p) => p.name || 'raíz').join(', ')}`;
  const out = [`■ ${pkg.name}  (${kind})`, `  ${formatSeverityCounts(pkg.counts)}`];
  if (pkg.error) return [...out, `  ⚠ ${pkg.error}`];

  const r = pkg.resolution!;
  if (r.status === 'ok' && r.recommended) {
    const rec = r.recommended;
    out.push(`  ${pkg.installed} → ${rec.version}  [${BUMP_LABEL[rec.bump]}]${r.quarantineBypassed ? '  ⚠ en cuarentena, se recomienda por ser crítica' : ''}`);
  } else if (r.status === 'quarantine-only' && r.waitingFor) {
    out.push(`  ${pkg.installed} → (esperar) ${r.waitingFor.version} sale de cuarentena el ${r.waitingFor.waitUntil?.slice(0, 10) ?? '?'} (${quarantineDays} días)`);
  } else {
    out.push(`  ${pkg.installed} → sin versión segura publicada`);
  }
  if (r.latest && r.latest.reason !== 'recommended') {
    const age = r.latest.ageDays !== undefined ? `, publicada hace ${Math.floor(r.latest.ageDays)} días` : '';
    out.push(`  Última: ${r.latest.version}${age} · ${LATEST_REASON[r.latest.reason]}`);
  }
  if (r.recommended?.bump === 'major' && !r.safeWithoutMajor) out.push('  No hay versión segura sin cambiar de major');

  if (pkg.auditFix.kind === 'audit-fix') out.push(`  npm audit fix ✓ (elegiría ${pkg.auditFix.version})`);
  else if (pkg.auditFix.kind === 'force') out.push('  npm pediría --force');
  else out.push('  No se puede predecir qué haría npm audit fix');

  const c = pkg.checks;
  if (c) {
    if (c.newInstallScripts.length > 0) out.push(`  ⚠ Agrega scripts de instalación: ${c.newInstallScripts.join(', ')}`);
    for (const p of c.peerChanges) out.push(`  peerDependencies · ${p.name}: ${p.from ?? '—'} → ${p.to ?? '—'}`);
    for (const p of c.peers.filter((p) => p.satisfied === false)) out.push(`  ⚠ ${p.name} ${p.installed} no cumple ${p.range}`);
    if (c.engines.from !== c.engines.to) out.push(`  engines.node: ${c.engines.from ?? '—'} → ${c.engines.to ?? '—'}`);
    if (c.engines.satisfiesProjectNode === false) out.push('  ⚠ Tu versión de Node no cumple engines.node de la nueva versión');
  }
  return out;
}
