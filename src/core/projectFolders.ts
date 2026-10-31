export const IGNORED_PROJECT_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

export interface ProjectFileEntry {
  path: string;
  kind: 'file' | 'directory';
}

/** Elige carpetas con manifest y lockfile, ordenando la raíz primero. */
export function projectCandidates(entries: readonly ProjectFileEntry[], maxDepth = 3): string[] {
  const files = new Set(entries.filter((e) => e.kind === 'file').map((e) => normalize(e.path)));
  const folders = new Set<string>();
  for (const file of files) {
    const match = file.match(/^(.*?)(?:\/)?(package(?:-lock)?\.json)$/);
    if (!match) continue;
    const folder = match[1] ?? '';
    const parts = folder ? folder.split('/') : [];
    if (parts.length > maxDepth || parts.some((part) => IGNORED_PROJECT_DIRS.has(part))) continue;
    const prefix = folder ? `${folder}/` : '';
    if (files.has(`${prefix}package.json`) && files.has(`${prefix}package-lock.json`)) folders.add(folder);
  }
  return [...folders].sort((a, b) => (a === '' ? -1 : b === '' ? 1 : a.localeCompare(b)));
}

function normalize(value: string): string {
  return value.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/$/, '');
}
