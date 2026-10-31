import { applyEdits, modify, parse } from 'jsonc-parser';
import { lineDiff, type DependencySection, type InstallPlan } from './plan';
import { isValidPackageName } from '../validate';

const SECTIONS: DependencySection[] = ['dependencies', 'devDependencies', 'optionalDependencies'];

export function buildRemovalPlan(manifestText: string, name: string): InstallPlan {
  if (!isValidPackageName(name)) throw new Error(`Invalid package name: ${name}`);
  const manifest = parse(manifestText) as Record<string, Record<string, unknown> | undefined>;
  const section = SECTIONS.find((key) => typeof manifest[key]?.[name] === 'string');
  if (!section) throw new Error(`${name} is not a direct dependency.`);
  const oldSpec = manifest[section]![name] as string;
  const eol = manifestText.includes('\r\n') ? '\r\n' : '\n';
  const indent = manifestText.match(/\n(\s+)["}]/)?.[1] ?? '  ';
  const options = indent.includes('\t') ? { insertSpaces: false, tabSize: 1, eol } : { insertSpaces: true, tabSize: indent.length, eol };
  let next = applyEdits(manifestText, modify(manifestText, [section, name], undefined, { formattingOptions: options }));
  if (manifestText.endsWith('\n') && !next.endsWith('\n')) next += eol;
  return {
    changes: [],
    removed: [{ name, section, oldSpec }],
    newManifestText: next,
    diff: lineDiff(manifestText, next),
    skipped: [],
  };
}

/** Motivo por el que una dependencia sin imports no debe ofrecerse para eliminar. */
export function removalBlockReason(manifestText: string, name: string, binNames: readonly string[], rootConfigs: readonly { path: string; text: string }[]): string | undefined {
  let manifest: any;
  try { manifest = JSON.parse(manifestText); } catch { return 'package.json could not be parsed'; }
  const needles = [name, ...binNames].filter(Boolean);
  for (const [script, command] of Object.entries(manifest.scripts ?? {})) {
    if (typeof command === 'string' && needles.some((needle) => commandToken(command, needle))) return `used by the ${script} script`;
  }
  for (const config of rootConfigs) {
    if (needles.some((needle) => config.text.includes(needle))) return `referenced by ${config.path}`;
  }
  return undefined;
}

function commandToken(command: string, needle: string): boolean {
  const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[\\s;&|])${escaped}(?=$|[\\s;&|:])`).test(command);
}
