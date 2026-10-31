import { createHash } from 'node:crypto';

export interface StableChange { name: string; from?: string; to?: string; removed?: boolean }

export function branchNameForChanges(changes: readonly StableChange[]): string {
  const canonical = [...changes].sort((a, b) => a.name.localeCompare(b.name)).map((c) => `${c.name}:${c.from ?? ''}:${c.to ?? ''}:${c.removed ? 'remove' : 'update'}`).join('\n');
  return `keel/fix-${createHash('sha256').update(canonical).digest('hex').slice(0, 8)}`;
}

export function isValidBranchName(value: string): boolean {
  return !value.startsWith('-') && /^(?!.*(?:\.\.|\/\/|@\{|\.lock(?:\/|$)))[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$/.test(value) && !/[/.]$/.test(value);
}

export function isValidBaseBranch(value: string): boolean {
  return value === '' || isValidBranchName(value);
}

/** Return porcelain paths outside the two files Keel is allowed to publish. */
export function unexpectedChanges(porcelainOutput: string, prefix: string): string[] {
  const allowed = new Set([`${prefix}package.json`, `${prefix}package-lock.json`]);
  const unexpected: string[] = [];
  for (const line of porcelainOutput.split(/\r?\n/).filter(Boolean)) {
    const status = line.slice(0, 2);
    const paths = splitRename(line.slice(3)).map(unquoteGitPath);
    if (status === '??') unexpected.push(...paths);
    else unexpected.push(...paths.filter((path) => !allowed.has(path)));
  }
  return unexpected;
}

function splitRename(value: string): string[] {
  let quoted = false;
  let escaped = false;
  for (let i = 0; i <= value.length - 4; i++) {
    const char = value[i]!;
    if (escaped) { escaped = false; continue; }
    if (quoted && char === '\\') { escaped = true; continue; }
    if (char === '"') quoted = !quoted;
    if (!quoted && value.slice(i, i + 4) === ' -> ') return [value.slice(0, i), value.slice(i + 4)];
  }
  return [value];
}

function unquoteGitPath(value: string): string {
  if (!value.startsWith('"') || !value.endsWith('"')) return value;
  return value.slice(1, -1).replace(/\\([0-7]{1,3}|[abfnrtv\\"])/g, (_match, escape: string) => {
    if (/^[0-7]/.test(escape)) return String.fromCharCode(Number.parseInt(escape, 8));
    return ({ a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', '"': '"' } as Record<string, string>)[escape] ?? escape;
  });
}
