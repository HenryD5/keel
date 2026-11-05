// Lectura de una lista externa de vulnerabilidades: una por línea, con códigos CVE/GHSA, título o ambos.
// Sin dependencias: lo usan la extensión, la CLI y el webview (vista previa de lo que se va a comparar).

const CVE = /\bCVE-\d{4}-\d{4,}\b/gi;
const GHSA = /\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b/gi;
const MAX_ITEMS = 500;

export interface ListItem {
  /** Líneas (1-based) del texto original en las que aparece. */
  lines: number[];
  ids: string[];
  title?: string;
}

/** Una línea por vulnerabilidad. Las líneas repetidas se agrupan; `,`/`;`/tabulador separan columnas. */
export function parseVulnerabilityList(text: string): ListItem[] {
  const byKey = new Map<string, ListItem>();
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const ids = [...new Set([...(line.match(CVE) ?? []), ...(line.match(GHSA) ?? [])].map(normalizeId))];
    const rest = line.replace(CVE, ' ').replace(GHSA, ' ').replace(/[\t,;|"]+/g, ' ').replace(/\s+/g, ' ').replace(/^[\s:–—-]+|[\s:–—-]+$/g, '').trim();
    const title = /[a-z]{3}/i.test(rest) ? rest : undefined;
    if (ids.length === 0 && !title) return;
    const key = `${ids.join(' ')}|${title?.toLowerCase() ?? ''}`;
    const item = byKey.get(key);
    if (item) item.lines.push(index + 1);
    else byKey.set(key, { lines: [index + 1], ids, title });
  });
  const items = [...byKey.values()];
  if (items.length > MAX_ITEMS) throw new Error(`The list has more than ${MAX_ITEMS} distinct entries.`);
  return items;
}

export function normalizeId(id: string): string {
  return id.toUpperCase().startsWith('GHSA') ? `GHSA${id.slice(4).toLowerCase()}` : id.toUpperCase();
}
