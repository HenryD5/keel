import type { VersionRelease } from './changelog';

export interface BreakingLine {
  version: string;
  text: string;
}

const MAX_LINES = 6;
const MAX_LENGTH = 240;

/**
 * Resumen sin IA: las líneas marcadas como BREAKING en las notas de cada release.
 * Toma los ítems bajo un título que diga "breaking" (hasta el siguiente título del mismo nivel o superior)
 * y cualquier línea que contenga "BREAKING" en mayúsculas (convención de Conventional Commits).
 */
export function extractBreakingLines(releases: readonly VersionRelease[], max = MAX_LINES): BreakingLine[] {
  const out: BreakingLine[] = [];
  const seen = new Set<string>();
  const push = (version: string, raw: string) => {
    const text = cleanMarkdown(raw);
    if (!text || seen.has(text.toLowerCase())) return;
    seen.add(text.toLowerCase());
    out.push({ version, text: text.length > MAX_LENGTH ? `${text.slice(0, MAX_LENGTH - 1)}…` : text });
  };

  for (const release of releases) {
    let sectionLevel = 0;
    for (const line of release.body.split(/\r?\n/)) {
      // Títulos markdown (`## Breaking Changes`) o una línea entera en negrita (`**Breaking changes:**`), que cuenta como el nivel más bajo.
      const heading = line.match(/^\s*(#{1,6})\s+(.*)$/);
      const level = heading ? heading[1]!.length : /^\s*\*\*[^*]+\*\*\s*:?\s*$/.test(line) ? 6 : 0;
      if (level > 0) {
        if (/breaking/i.test(heading?.[2] ?? line)) sectionLevel = level;
        else if (sectionLevel && level <= sectionLevel) sectionLevel = 0;
        continue;
      }
      if (sectionLevel && /^\s*(?:[-*+]|\d+\.)\s+/.test(line)) push(release.version, line);
      else if (!sectionLevel && /\bBREAKING\b/.test(line)) push(release.version, line);
    }
  }
  return out.slice(0, max);
}

/** Quita viñetas, énfasis, enlaces y prefijos `BREAKING CHANGE:` para mostrar una línea limpia. */
export function cleanMarkdown(line: string): string {
  return line
    .replace(/^\s*(?:[-*+]|\d+\.)\s+/, '')
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/\*\*|__|`/g, '')
    .replace(/^\s*(?:⚠️?\s*)?BREAKING(?:\s+CHANGES?)?\s*[:-]\s*/i, '')
    .replace(/\s+/g, ' ')
    .trim();
}
