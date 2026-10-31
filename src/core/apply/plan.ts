import { applyEdits, modify, parse, type FormattingOptions } from 'jsonc-parser';
import type { ScanResult } from '../scan';
import { assertPackageName, assertVersion } from '../validate';
import type { Bump } from '../resolver/versions';

export type DependencySection = 'dependencies' | 'devDependencies' | 'optionalDependencies';

export interface InstallChange {
  name: string;
  from: string;
  to: string;
  bump: Bump;
  kind: 'direct' | 'override';
  section?: DependencySection;
  oldSpec?: string;
  newSpec: string;
}

export interface DiffLine {
  kind: 'context' | 'del' | 'add';
  text: string;
}

export interface InstallPlan {
  /** Pinning choice is part of the approved plan and therefore its plan ID. */
  exact?: boolean;
  changes: InstallChange[];
  removed?: Array<{ name: string; section: DependencySection; oldSpec: string }>;
  newManifestText: string;
  diff: DiffLine[];
  skipped: Array<{ name: string; reason: string }>;
}

export interface BuildInstallPlanInput {
  result: ScanResult;
  manifestText: string;
  selected: string[];
  choices: Record<string, 'min' | 'latest'>;
  exact: boolean;
}

interface Manifest {
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  overrides?: Record<string, unknown>;
}

/** Construye las ediciones de package.json sin reordenar sus claves. */
export function buildInstallPlan(input: BuildInstallPlanInput): InstallPlan {
  const manifest = parse(input.manifestText) as Manifest;
  const formattingOptions = detectFormatting(input.manifestText);
  const hadFinalEol = hasFinalEol(input.manifestText);
  let text = input.manifestText;
  const changes: InstallChange[] = [];
  const skipped: InstallPlan['skipped'] = [];
  const reports = new Map(input.result.packages.map((pkg) => [pkg.name, pkg]));

  for (const selectedName of input.selected) {
    const name = assertPackageName(selectedName);
    const pkg = reports.get(name);
    if (!pkg) {
      skipped.push({ name, reason: 'not-found' });
      continue;
    }

    const resolution = pkg.resolution;
    const latest = resolution?.latest;
    const useLatest =
      input.choices[name] === 'latest' && latest !== undefined && (latest.reason === 'not-needed' || latest.reason === 'major-avoided');
    const target = useLatest ? latest : resolution?.recommended;
    if (!target) {
      skipped.push({ name, reason: pkg.error ? 'error' : (resolution?.status ?? 'no-recommendation') });
      continue;
    }

    const to = assertVersion(target.version);
    const from = assertVersion(pkg.installed);
    if (pkg.direct) {
      const section = sectionFor(pkg.depType);
      const oldValue = manifest[section]?.[name];
      const oldSpec = typeof oldValue === 'string' ? oldValue : pkg.declaredRange;
      const newSpec = input.exact ? to : rangeFor(oldSpec, to);
      text = edit(text, [section, name], newSpec, formattingOptions);
      if (!manifest[section]) manifest[section] = {};
      manifest[section]![name] = newSpec;
      changes.push({ name, from, to, bump: target.bump, kind: 'direct', section, oldSpec, newSpec });
    } else {
      const oldSpec = asString(manifest.overrides?.[name]);
      text = edit(text, ['overrides', name], to, formattingOptions);
      if (!manifest.overrides) manifest.overrides = {};
      manifest.overrides[name] = to;
      changes.push({ name, from, to, bump: target.bump, kind: 'override', oldSpec, newSpec: to });
    }
  }

  text = preserveFinalEol(text, hadFinalEol, formattingOptions.eol ?? '\n');
  return { exact: input.exact, changes, newManifestText: text, diff: lineDiff(input.manifestText, text), skipped };
}

function sectionFor(depType: string | undefined): DependencySection {
  if (depType === 'dev') return 'devDependencies';
  if (depType === 'optional') return 'optionalDependencies';
  return 'dependencies';
}

function rangeFor(oldSpec: string | undefined, version: string): string {
  if (oldSpec && /^\^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(oldSpec)) return `^${version}`;
  if (oldSpec && /^~\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(oldSpec)) return `~${version}`;
  if (oldSpec && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(oldSpec)) return version;
  return `^${version}`;
}

function edit(text: string, path: (string | number)[], value: unknown, options: FormattingOptions): string {
  return applyEdits(text, modify(text, path, value, { formattingOptions: options }));
}

function detectFormatting(text: string): FormattingOptions {
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const lines = text.split(/\r?\n/);
  const indented = lines.find((line) => /^(\t+| +)\S/.test(line));
  const prefix = indented?.match(/^(\t+| +)/)?.[0] ?? '  ';
  return prefix.includes('\t')
    ? { insertSpaces: false, tabSize: 1, eol }
    : { insertSpaces: true, tabSize: prefix.length, eol };
}

function hasFinalEol(text: string): boolean {
  return text.endsWith('\n');
}

function preserveFinalEol(text: string, wanted: boolean, eol: string): string {
  const without = text.replace(/(?:\r?\n)+$/, '');
  return wanted ? without + eol : without;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

interface RawDiffLine extends DiffLine {
  changed: boolean;
}

/** Diff LCS con una línea de contexto alrededor de cada bloque. */
export function lineDiff(before: string, after: string): DiffLine[] {
  if (before === after) return [];
  const a = splitLines(before);
  const b = splitLines(after);
  const lengths = Array.from({ length: a.length + 1 }, () => new Array<number>(b.length + 1).fill(0));
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      lengths[i]![j] = a[i] === b[j] ? lengths[i + 1]![j + 1]! + 1 : Math.max(lengths[i + 1]![j]!, lengths[i]![j + 1]!);
    }
  }

  const raw: RawDiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    if (i < a.length && j < b.length && a[i] === b[j]) {
      raw.push({ kind: 'context', text: a[i]!, changed: false });
      i++;
      j++;
    } else if (j < b.length && (i === a.length || lengths[i]![j + 1]! > lengths[i + 1]![j]!)) {
      raw.push({ kind: 'add', text: b[j++]!, changed: true });
    } else {
      raw.push({ kind: 'del', text: a[i++]!, changed: true });
    }
  }

  const changed = raw.flatMap((line, index) => (line.changed ? [index] : []));
  const ranges: Array<[number, number]> = [];
  for (const index of changed) {
    const start = Math.max(0, index - 1);
    const end = Math.min(raw.length - 1, index + 1);
    const previous = ranges.at(-1);
    if (previous && start <= previous[1] + 1) previous[1] = Math.max(previous[1], end);
    else ranges.push([start, end]);
  }

  return ranges.flatMap(([start, end], index) => [
    ...(index > 0 ? [{ kind: 'context' as const, text: '…' }] : []),
    ...raw.slice(start, end + 1).map(({ kind, text }) => ({ kind, text })),
  ]);
}

function splitLines(text: string): string[] {
  const lines = text.split(/\r?\n/);
  if (lines.at(-1) === '') lines.pop();
  return lines;
}
