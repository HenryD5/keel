export interface RegistryFinding {
  package: string;
  host: string;
  reason: 'unapproved-host' | 'insecure-http' | 'git-url';
}

const DEFAULT_HOST = 'registry.npmjs.org';

function hostOf(value: string): string | undefined {
  try {
    return new URL(value.trim()).hostname.toLowerCase() || undefined;
  } catch {
    return undefined;
  }
}

export function allowedHosts(npmrcText: string, configuredRegistry?: string): Set<string> {
  const hosts = new Set<string>([DEFAULT_HOST]);
  for (const raw of npmrcText.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const registry = line.match(/^(?:registry|@[^:]+:registry)\s*=\s*(.+)$/i)?.[1];
    const authHost = line.match(/^\/\/([^/\s]+)\//)?.[1];
    const host = registry ? hostOf(registry) : authHost?.split(':')[0]?.toLowerCase();
    if (host) hosts.add(host);
  }
  const configured = configuredRegistry && hostOf(configuredRegistry);
  if (configured) hosts.add(configured);
  return hosts;
}

export function findDisallowedRegistries(lockText: string, hosts: ReadonlySet<string>): RegistryFinding[] {
  let lock: any;
  try {
    lock = JSON.parse(lockText);
  } catch {
    return [];
  }
  const out: RegistryFinding[] = [];
  const inspect = (name: string, resolved: unknown, link = false) => {
    if (link || typeof resolved !== 'string' || resolved.startsWith('file:')) return;
    if (/^(?:git\+|git:|github:|git@)/i.test(resolved)) {
      out.push({ package: name, host: hostOf(resolved.replace(/^git\+/, '')) ?? 'git', reason: 'git-url' });
      return;
    }
    let url: URL;
    try { url = new URL(resolved); } catch { return; }
    const host = url.hostname.toLowerCase();
    if (url.protocol === 'http:') out.push({ package: name, host, reason: 'insecure-http' });
    else if (!hosts.has(host)) out.push({ package: name, host, reason: 'unapproved-host' });
  };
  for (const [path, pkg] of Object.entries<any>(lock?.packages ?? {})) {
    if (!path) continue;
    inspect(pkg?.name ?? packageFromPath(path), pkg?.resolved, pkg?.link === true);
  }
  const walk = (deps: any) => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, dep] of Object.entries<any>(deps)) {
      inspect(name, dep?.resolved ?? dep?.version, dep?.link === true);
      walk(dep?.dependencies);
    }
  };
  // lockfile v2 repite la misma información en `packages` y `dependencies`.
  if (!lock?.packages) walk(lock?.dependencies);
  return out;
}

export function newRegistryFindings(before: readonly RegistryFinding[], after: readonly RegistryFinding[]): RegistryFinding[] {
  const keys = new Set(before.map(findingKey));
  return after.filter((finding) => !keys.has(findingKey(finding)));
}

function findingKey(f: RegistryFinding): string {
  return `${f.package}\0${f.host}\0${f.reason}`;
}

function packageFromPath(path: string): string {
  const tail = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
  return tail.startsWith('@') ? tail.split('/').slice(0, 2).join('/') : tail.split('/')[0] ?? path;
}
