import { categoryByKey } from './categories';
import type { VerifyItem, VerifyResult, VerifyStatus } from './verify';

type Lang = 'en' | 'es';

const STATUS: Record<VerifyStatus, { en: string; es: string }> = {
  fixed: { en: 'fixed — installed version is not affected', es: 'corregido — la versión instalada no está afectada' },
  'not-installed': { en: 'resolved — affected package is no longer installed', es: 'resuelto — el paquete afectado ya no está instalado' },
  'no-remaining': { en: 'likely resolved — npm audit reports nothing of this type', es: 'probablemente resuelto — npm audit no reporta nada de este tipo' },
  vulnerable: { en: 'STILL VULNERABLE', es: 'SIGUE VULNERABLE' },
  remaining: { en: 'PENDING — advisories of this type remain', es: 'PENDIENTE — quedan avisos de este tipo' },
  'unknown-id': { en: 'unverified — OSV does not know this ID', es: 'sin verificar — OSV no conoce este código' },
  'not-npm': { en: 'unverified — the advisory does not affect npm packages', es: 'sin verificar — el aviso no afecta a paquetes npm' },
  unmapped: { en: 'unverified — type not recognized; add the CVE to check it', es: 'sin verificar — tipo no reconocido; añade el CVE para comprobarlo' },
  error: { en: 'unverified — lookup failed', es: 'sin verificar — falló la consulta' },
};

const ICON = { resolved: '✅', pending: '❌', unverified: '⚠️' } as const;

export function formatVerifyResult(result: VerifyResult, lang: Lang): string {
  const t = (en: string, es: string) => (lang === 'es' ? es : en);
  const { totals } = result;
  const lines: string[] = [];
  lines.push(t('# Vulnerability list check', '# Verificación de la lista de vulnerabilidades'), '');
  lines.push(
    t(
      `${totals.lines} entries (${totals.distinct} distinct): ${totals.resolved} resolved, ${totals.pending} pending, ${totals.unverified} unverified.`,
      `${totals.lines} entradas (${totals.distinct} distintas): ${totals.resolved} resueltas, ${totals.pending} pendientes, ${totals.unverified} sin verificar.`,
    ),
  );
  lines.push(
    result.allResolved
      ? t('**Everything on the list is resolved.**', '**Todo lo de la lista está resuelto.**')
      : totals.pending > 0
        ? t('**Not everything is fixed yet.**', '**Aún no está todo corregido.**')
        : t('**Nothing is pending, but some entries could not be verified.**', '**No queda nada pendiente, pero hay entradas que no se pudieron verificar.**'),
    '',
  );
  const order = ['pending', 'unverified', 'resolved'] as const;
  for (const outcome of order) {
    const group = result.items.filter((i) => i.outcome === outcome);
    if (group.length === 0) continue;
    lines.push(`## ${ICON[outcome]} ${t({ pending: 'Pending', unverified: 'Unverified', resolved: 'Resolved' }[outcome], { pending: 'Pendientes', unverified: 'Sin verificar', resolved: 'Resueltas' }[outcome])}`, '');
    for (const item of group) lines.push(...formatItem(item, lang), '');
  }
  if (result.items.some((i) => i.ids.length === 0 && i.category)) {
    lines.push(
      t(
        '_Title-only entries are matched by vulnerability type (CWE), not by a specific advisory. Add the CVE or GHSA code for an exact check._',
        '_Las entradas con solo título se cruzan por tipo de vulnerabilidad (CWE), no por un aviso concreto. Añade el código CVE o GHSA para una comprobación exacta._',
      ),
    );
  }
  return lines.join('\n').trimEnd();
}

function formatItem(item: VerifyItem, lang: Lang): string[] {
  const t = (en: string, es: string) => (lang === 'es' ? es : en);
  const name = [item.ids.join(', '), item.title].filter(Boolean).join(' — ');
  const times = item.lines.length > 1 ? ` ×${item.lines.length}` : '';
  const out = [`- **${name}**${times}: ${STATUS[item.status][lang]}`];
  const category = item.category ? categoryByKey(item.category) : undefined;
  if (item.ids.length === 0 && category) out.push(`  - ${t('Type', 'Tipo')}: ${category.label[lang]} (${category.cwes.join(', ')})`);
  for (const check of item.checks) {
    const detail = [check.aliases.length ? check.aliases.join(', ') : undefined, check.packages.length ? check.packages.join(', ') : undefined].filter(Boolean).join(' · ');
    if (item.checks.length > 1) out.push(`  - ${check.id}${detail ? ` (${detail})` : ''}: ${STATUS[check.status][lang]}`);
    else if (detail) out.push(`  - ${detail}`);
    for (const v of check.vulnerable) out.push(`    - ${v.package}@${v.version} \`${v.path}\`${v.fixedIn ? ` → ${t('fixed in', 'corregido en')} ${v.fixedIn}` : ''}`);
    if (check.status === 'vulnerable' && check.vulnerable.length === 0 && check.inAudit) out.push(`    - ${t('still reported by npm audit', 'npm audit todavía lo reporta')}`);
    if (check.status === 'fixed') out.push(`    - ${[...new Set(check.safe.map((s) => `${s.package}@${s.version}`))].join(', ')}`);
    if (check.error) out.push(`    - ${check.error}`);
  }
  if (item.titleMatches === false) out.push(`  - ${t('Note: the code does not look like this vulnerability type; check the list.', 'Ojo: el código no parece de este tipo de vulnerabilidad; revisa la lista.')}`);
  for (const c of item.candidates.slice(0, 10)) out.push(`  - ${c.package}: ${c.id} — ${c.title} (${c.severity}${c.cwe.length ? `, ${c.cwe.join(', ')}` : ''})`);
  if (item.candidates.length > 10) out.push(`  - … ${t(`${item.candidates.length - 10} more`, `${item.candidates.length - 10} más`)}`);
  return out;
}
