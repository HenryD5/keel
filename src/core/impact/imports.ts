export type ImportKind = 'import' | 'require' | 'dynamic-import';

/** Un punto del código donde se usa el paquete. */
export interface Usage {
  /** 1-based. */
  line: number;
  kind: ImportKind;
  /** Lo que se usa en esa línea: `jwt.verify`, `verify`, `axios`… o la propia importación si no hay más. */
  symbol: string;
}

interface Binding {
  local: string;
  /** Nombre exportado (`verify` en `import { verify as v }`). Sin él, es el módulo entero (default o namespace). */
  imported?: string;
}

interface ImportSite {
  index: number;
  end: number;
  kind: ImportKind;
  bindings: Binding[];
}

const IDENT = '[A-Za-z_$][\\w$]*';

/** Extensiones donde se buscan importaciones. */
export const SOURCE_EXTENSIONS = ['js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts', 'vue', 'svelte'] as const;

/**
 * Busca dónde se usa `pkg` en un archivo: `import`, `require` e `import()`, también con subrutas (`pkg/sub`).
 * Devuelve cada llamada o acceso a lo importado (`jwt.verify`, `verify(`); si lo importado no se usa más
 * en el archivo, devuelve la línea de la importación. Es un análisis por texto, sin AST: ignora comentarios
 * de línea y de bloque, pero no distingue nombres que se sombrean dentro de una función.
 */
export function findUsages(source: string, pkg: string): Usage[] {
  const code = blankComments(source);
  const sites = findImportSites(code, pkg);
  const lineAt = lineIndex(code);
  const usages: Usage[] = [];

  for (const site of sites) {
    const found: Usage[] = [];
    for (const b of site.bindings) {
      const name = escapeRegExp(b.local);
      if (b.imported === undefined) {
        // Módulo entero: `jwt.verify`, `jwt(` o `new Foo(`.
        for (const m of matchAllOutside(code, new RegExp(`(?<![\\w$.])${name}\\s*(?:\\?\\.|\\.)\\s*(${IDENT})`, 'g'), sites)) {
          found.push({ line: lineAt(m.index!), kind: site.kind, symbol: `${b.local}.${m[1]}` });
        }
        for (const m of matchAllOutside(code, new RegExp(`(?<![\\w$.])${name}\\s*\\(`, 'g'), sites)) {
          found.push({ line: lineAt(m.index!), kind: site.kind, symbol: b.local });
        }
      } else {
        for (const m of matchAllOutside(code, new RegExp(`(?<![\\w$.])${name}(?![\\w$])\\s*(?:\\(|\\.|<)`, 'g'), sites)) {
          found.push({ line: lineAt(m.index!), kind: site.kind, symbol: b.imported });
        }
      }
    }
    if (found.length === 0) {
      const symbol = site.bindings.map((b) => b.imported ?? b.local).join(', ') || pkg;
      found.push({ line: lineAt(site.index), kind: site.kind, symbol });
    }
    usages.push(...found);
  }

  return dedupe(usages).sort((a, b) => a.line - b.line || a.symbol.localeCompare(b.symbol));
}

function findImportSites(code: string, pkg: string): ImportSite[] {
  // Especificador entre comillas; `group` es el número del grupo de la comilla dentro de cada regex.
  const spec = (group: number) => `(['"\`])${escapeRegExp(pkg)}(?:/[^'"\`]*)?\\${group}`;
  const sites: ImportSite[] = [];
  const add = (m: RegExpMatchArray, kind: ImportKind, bindings: Binding[]) =>
    sites.push({ index: m.index!, end: m.index! + m[0].length, kind, bindings });

  // import X from 'pkg' · import * as X from 'pkg' · import { a, b as c } from 'pkg' · import X, { a } from 'pkg' · import 'pkg'
  for (const m of code.matchAll(new RegExp(`\\bimport\\s+(?:type\\s+)?([^'"\`;]*?)\\s*from\\s*${spec(2)}`, 'g'))) {
    add(m, 'import', parseImportClause(m[1]!));
  }
  for (const m of code.matchAll(new RegExp(`\\bimport\\s*${spec(1)}`, 'g'))) add(m, 'import', []);
  // export { a } from 'pkg' · export * from 'pkg'
  for (const m of code.matchAll(new RegExp(`\\bexport\\s+(?:type\\s+)?(?:\\*(?:\\s+as\\s+${IDENT})?|\\{[^}]*\\})\\s*from\\s*${spec(1)}`, 'g'))) {
    add(m, 'import', []);
  }
  // const X = require('pkg') · const { a, b: c } = require('pkg') · require('pkg')
  // const X = await import('pkg') · import('pkg')
  for (const [fn, kind] of [
    ['require', 'require'],
    ['(?:await\\s+)?import', 'dynamic-import'],
  ] as const) {
    const call = `\\b${fn}\\s*\\(\\s*${spec(2)}\\s*\\)`;
    const re = new RegExp(`(?:\\b(?:const|let|var)\\s+(${IDENT}|\\{[^}]*\\})\\s*=\\s*)?${call}(\\s*\\.\\s*(${IDENT}))?`, 'g');
    for (const m of code.matchAll(re)) {
      if (kind === 'dynamic-import' && /\bimport\s+[^(]/.test(m[0])) continue;
      const target = m[1];
      const member = m[4];
      let bindings: Binding[] = [];
      if (target?.startsWith('{')) bindings = parseDestructure(target);
      else if (target && member) bindings = [{ local: target, imported: member }];
      else if (target) bindings = [{ local: target }];
      add(m, kind, bindings);
    }
  }
  return sites.sort((a, b) => a.index - b.index);
}

function parseImportClause(clause: string): Binding[] {
  const bindings: Binding[] = [];
  const named = clause.match(/\{([^}]*)\}/);
  const rest = clause.replace(/\{[^}]*\}/, '').replace(/,/g, ' ').trim();
  const ns = rest.match(new RegExp(`\\*\\s*as\\s+(${IDENT})`));
  if (ns) bindings.push({ local: ns[1]! });
  const def = rest.replace(/\*\s*as\s+\S+/, '').trim();
  if (def && new RegExp(`^${IDENT}$`).test(def)) bindings.push({ local: def });
  if (named) {
    for (const part of named[1]!.split(',')) {
      const m = part.trim().match(new RegExp(`^(?:type\\s+)?(${IDENT}|'[^']+'|"[^"]+")(?:\\s+as\\s+(${IDENT}))?$`));
      if (!m) continue;
      const imported = m[1]!.replace(/^['"]|['"]$/g, '');
      bindings.push(imported === 'default' && m[2] ? { local: m[2] } : { local: m[2] ?? imported, imported });
    }
  }
  return bindings;
}

function parseDestructure(pattern: string): Binding[] {
  const out: Binding[] = [];
  for (const part of pattern.slice(1, -1).split(',')) {
    const m = part.trim().match(new RegExp(`^(${IDENT})(?:\\s*:\\s*(${IDENT}))?`));
    if (!m) continue;
    out.push(m[1] === 'default' && m[2] ? { local: m[2] } : { local: m[2] ?? m[1]!, imported: m[1]! });
  }
  return out;
}

/** Coincidencias que no caen dentro de una sentencia de importación. */
function* matchAllOutside(code: string, re: RegExp, sites: readonly ImportSite[]): Generator<RegExpMatchArray> {
  for (const m of code.matchAll(re)) {
    if (!sites.some((s) => m.index! >= s.index && m.index! < s.end)) yield m;
  }
}

/** Reemplaza comentarios por espacios conservando saltos de línea, para que los índices y las líneas no cambien. */
function blankComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\/|(?<![:'"\\])\/\/[^\n]*/g, (c) => c.replace(/[^\n]/g, ' '));
}

function lineIndex(code: string): (index: number) => number {
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code[i] === '\n') starts.push(i + 1);
  return (index) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid]! <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

function dedupe(usages: Usage[]): Usage[] {
  const seen = new Set<string>();
  return usages.filter((u) => {
    const key = `${u.line}|${u.symbol}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
