import { categoryByKey } from './categories';
import type { VerifyItem, VerifyResult, VerifyStatus } from './verify';

type Lang = 'en' | 'es';

export const STATUS_TEXT: Record<VerifyStatus, { en: string; es: string }> = {
  fixed: { en: 'Fixed: the installed version no longer has it', es: 'Corregido: la versión instalada ya no la tiene' },
  'not-installed': { en: 'Fixed: the affected package is no longer installed', es: 'Corregido: el paquete afectado ya no está instalado' },
  'no-remaining': { en: 'Probably fixed: nothing of this type is still open', es: 'Probablemente corregido: no queda nada abierto de este tipo' },
  vulnerable: { en: 'Still open: the installed version has it', es: 'Sigue abierto: la versión instalada todavía la tiene' },
  remaining: { en: 'Still open: vulnerabilities of this type remain', es: 'Sigue abierto: quedan vulnerabilidades de este tipo' },
  'unknown-id': { en: 'Not checked: this code was not found in OSV', es: 'Sin comprobar: este código no aparece en OSV' },
  'not-npm': { en: 'Not checked: it does not affect npm packages', es: 'Sin comprobar: no afecta a paquetes npm' },
  unmapped: { en: 'Not checked: unknown type; add its CVE', es: 'Sin comprobar: tipo no reconocido; añade su CVE' },
  error: { en: 'Not checked: the lookup failed', es: 'Sin comprobar: falló la consulta' },
};

const ICON = { resolved: '✅', pending: '❌', unverified: '⚠️' } as const;

export function formatVerifyResult(result: VerifyResult, lang: Lang): string {
  const t = (en: string, es: string) => (lang === 'es' ? es : en);
  const { totals } = result;
  const lines: string[] = [];
  lines.push(t('# Comparison with the vulnerability report', '# Comparación con el reporte de vulnerabilidades'), '');
  lines.push(
    t(
      `${totals.lines} findings (${totals.distinct} distinct): ${totals.resolved} fixed, ${totals.pending} open, ${totals.unverified} not checked.`,
      `${totals.lines} hallazgos (${totals.distinct} distintos): ${totals.resolved} corregidos, ${totals.pending} abiertos, ${totals.unverified} sin comprobar.`,
    ),
  );
  lines.push(
    result.allResolved
      ? t('**Everything reported is fixed.**', '**Todo lo reportado está corregido.**')
      : totals.pending > 0
        ? t('**Some findings are still open.**', '**Todavía quedan hallazgos abiertos.**')
        : t('**Nothing is open, but some findings could not be checked.**', '**No queda nada abierto, pero algunos hallazgos no se pudieron comprobar.**'),
    '',
  );
  const order = ['pending', 'unverified', 'resolved'] as const;
  for (const outcome of order) {
    const group = result.items.filter((i) => i.outcome === outcome);
    if (group.length === 0) continue;
    lines.push(`## ${ICON[outcome]} ${t({ pending: 'Open', unverified: 'Not checked', resolved: 'Fixed' }[outcome], { pending: 'Abiertos', unverified: 'Sin comprobar', resolved: 'Corregidos' }[outcome])}`, '');
    for (const item of group) lines.push(...formatItem(item, lang), '');
  }
  if (result.items.some((i) => i.ids.length === 0 && i.category)) {
    lines.push(
      t(
        '_Title-only findings are matched by vulnerability type (CWE), not by a specific advisory. Add the CVE or GHSA code for an exact check._',
        '_Los hallazgos con solo título se comparan por tipo de vulnerabilidad (CWE), no por un aviso concreto. Añade el código CVE o GHSA para una comprobación exacta._',
      ),
    );
  }
  return lines.join('\n').trimEnd();
}

function formatItem(item: VerifyItem, lang: Lang): string[] {
  const t = (en: string, es: string) => (lang === 'es' ? es : en);
  const name = [item.ids.join(', '), item.title].filter(Boolean).join(' — ');
  const times = item.lines.length > 1 ? ` ×${item.lines.length}` : '';
  const out = [`- **${name}**${times}: ${STATUS_TEXT[item.status][lang]}`];
  const category = item.category ? categoryByKey(item.category) : undefined;
  if (item.ids.length === 0 && category) out.push(`  - ${t('Type', 'Tipo')}: ${category.label[lang]} (${category.cwes.join(', ')})`);
  for (const check of item.checks) {
    const detail = [check.aliases.length ? check.aliases.join(', ') : undefined, check.packages.length ? check.packages.join(', ') : undefined].filter(Boolean).join(' · ');
    if (item.checks.length > 1) out.push(`  - ${check.id}${detail ? ` (${detail})` : ''}: ${STATUS_TEXT[check.status][lang]}`);
    else if (detail) out.push(`  - ${detail}`);
    for (const v of check.vulnerable) out.push(`    - ${v.package}@${v.version} \`${v.path}\`${v.fixedIn ? ` → ${t('fixed in', 'corregido en')} ${v.fixedIn}` : ''}`);
    if (check.status === 'vulnerable' && check.vulnerable.length === 0 && check.inAudit) out.push(`    - ${t('still reported by npm audit', 'npm audit todavía lo reporta')}`);
    if (check.status === 'fixed') out.push(`    - ${[...new Set(check.safe.map((s) => `${s.package}@${s.version}`))].join(', ')}`);
    if (check.error) out.push(`    - ${check.error}`);
  }
  if (item.titleMatches === false) out.push(`  - ${t('Note: the code does not look like this vulnerability type; check the list.', 'Ojo: el código no parece de este tipo de vulnerabilidad; revisa la lista.')}`);
  for (const c of item.candidates.slice(0, 10)) out.push(`  - ${c.package}: ${c.id}${c.cves.length ? ` (${c.cves.join(', ')})` : ''} — ${c.title} (${c.severity}${c.cwe.length ? `, ${c.cwe.join(', ')}` : ''})`);
  if (item.candidates.length > 10) out.push(`  - … ${t(`${item.candidates.length - 10} more`, `${item.candidates.length - 10} más`)}`);
  return out;
}
