import { readdir, readFile } from 'node:fs/promises';
import { extname, relative } from 'node:path';
import { findUsages, SOURCE_EXTENSIONS, type Usage } from './imports';

const IGNORED = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);
const EXTENSIONS = new Set(SOURCE_EXTENSIONS.map((ext) => `.${ext}`));

export interface FileUsages { path: string; usages: Usage[] }

export async function findProjectUsages(root: string, packageName: string): Promise<FileUsages[]> {
  const out: FileUsages[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory() && IGNORED.has(entry.name)) continue;
      const full = `${dir}/${entry.name}`;
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && EXTENSIONS.has(extname(entry.name))) {
        const usages = findUsages(await readFile(full, 'utf8'), packageName);
        if (usages.length) out.push({ path: relative(root, full).replace(/\\/g, '/'), usages });
      }
    }
  };
  await walk(root);
  return out;
}
