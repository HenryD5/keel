import semver from 'semver';
import type { Lockfile } from '../audit/lockfile';
import type { Packument } from '../registry/types';

// Antes de `npm install`: ¿alguna versión planificada choca con las peerDependencies del proyecto?
// npm falla con ERESOLVE en esos casos (p. ej. vitest 3.2.7 exige @vitest/ui 3.2.7 y
// @vitest/coverage-v8 3.2.6 exige vitest 3.2.6). Keel nunca usa --force ni --legacy-peer-deps:
// propone actualizar juntos los paquetes hermanos.

export interface PlannedVersion {
  name: string;
  to: string;
}

export interface PeerConflict {
  /** Paquete cuya peerDependency no se cumple. */
  requirer: string;
  requirerVersion: string;
  /** Paquete pedido como peer y la versión que tendría tras el plan. */
  peer: string;
  peerVersion: string;
  range: string;
  optional: boolean;
  /** Paquete que Keel propone cambiar para resolverlo (el que no está en el plan). */
  fix?: { name: string; from: string; to: string };
}

export interface PeerCheckInput {
  planned: readonly PlannedVersion[];
  lock: Lockfile;
  getPackument(name: string): Promise<Packument>;
}

/** Conflictos de peerDependencies que tendría el árbol después del plan, con la versión que los resolvería. */
export async function findPeerConflicts(input: PeerCheckInput): Promise<PeerConflict[]> {
  const planned = new Map(input.planned.map((p) => [p.name, p.to]));
  const installed = (name: string) => input.lock.packages.get(`node_modules/${name}`)?.version;
  const effective = (name: string) => planned.get(name) ?? installed(name);

  /** peerDependencies de un paquete en la versión que tendrá: del registro si cambia, del lockfile si no. */
  const peersOf = async (name: string): Promise<Array<{ peer: string; range: string; optional: boolean }>> => {
    const to = planned.get(name);
    if (to) {
      const manifest = (await input.getPackument(name)).versions[to];
      const meta = manifest?.peerDependenciesMeta ?? {};
      return Object.entries(manifest?.peerDependencies ?? {}).map(([peer, range]) => ({ peer, range, optional: meta[peer]?.optional === true }));
    }
    const node = input.lock.packages.get(`node_modules/${name}`);
    return [...(node?.deps ?? [])].filter(([, d]) => d.type === 'peer').map(([peer, d]) => ({ peer, range: d.range, optional: false }));
  };

  // Se revisan los paquetes planificados y los instalados que piden como peer alguno de ellos.
  const toCheck = new Set<string>(planned.keys());
  for (const pkg of input.lock.packages.values()) {
    if (pkg.path !== `node_modules/${pkg.name}` || pkg.link) continue;
    if ([...pkg.deps].some(([dep, d]) => d.type === 'peer' && planned.has(dep))) toCheck.add(pkg.name);
  }

  const conflicts: PeerConflict[] = [];
  for (const requirer of [...toCheck].sort()) {
    const requirerVersion = effective(requirer);
    if (!requirerVersion) continue;
    for (const { peer, range, optional } of await peersOf(requirer)) {
      // Solo importan los peers que cambian o los que pide un paquete que cambia.
      if (!planned.has(requirer) && !planned.has(peer)) continue;
      const peerVersion = effective(peer);
      // Un peer que no está instalado lo resuelve npm (o es opcional): no es un conflicto.
      if (!peerVersion || !semver.valid(peerVersion) || semver.satisfies(peerVersion, range, { includePrerelease: true })) continue;
      conflicts.push({ requirer, requirerVersion, peer, peerVersion, range, optional });
    }
  }

  for (const conflict of conflicts) conflict.fix = await suggestFix(conflict, planned, installed, input.getPackument);
  return conflicts;
}

/**
 * Lo que pide un paquete planificado se resuelve moviendo el peer; lo que pide un paquete que no cambia,
 * moviendo a ese paquete. Si los dos están en el plan, el choque es entre elecciones del dev: no se propone nada.
 * Se prefiere la misma versión que la planificada (paquetes de un monorepo, como @vitest/*) y si no,
 * la más baja compatible por encima de la instalada.
 */
async function suggestFix(
  c: PeerConflict,
  planned: ReadonlyMap<string, string>,
  installed: (name: string) => string | undefined,
  getPackument: (name: string) => Promise<Packument>,
): Promise<PeerConflict['fix']> {
  if (planned.has(c.requirer) === planned.has(c.peer)) return undefined;
  const movePeer = planned.has(c.requirer);
  const name = movePeer ? c.peer : c.requirer;
  const anchor = movePeer ? c.requirer : c.peer;
  const anchorVersion = planned.get(anchor)!;
  const from = installed(name);
  if (!from) return undefined;
  let packument: Packument;
  try {
    packument = await getPackument(name);
  } catch {
    return undefined;
  }
  const fits = (v: string) => {
    const manifest = packument.versions[v];
    if (!manifest || manifest.deprecated) return false;
    if (movePeer && !semver.satisfies(v, c.range, { includePrerelease: true })) return false;
    // La versión nueva no puede pedir, a su vez, otra versión del paquete planificado.
    return acceptsPeer(manifest.peerDependencies, anchor, anchorVersion);
  };
  const candidates = Object.keys(packument.versions).filter((v) => semver.valid(v) && semver.prerelease(v) === null && fits(v)).sort(semver.compare);
  const to = (candidates.includes(anchorVersion) ? anchorVersion : undefined) ?? candidates.find((v) => semver.gt(v, from)) ?? candidates.at(-1);
  return to && to !== from ? { name, from, to } : undefined;
}

function acceptsPeer(peers: Record<string, string> | undefined, name: string, version: string | undefined): boolean {
  const range = peers?.[name];
  return !range || !version || semver.satisfies(version, range, { includePrerelease: true });
}
