import semver from 'semver';
import type { VersionManifest } from '../registry/types';

export const INSTALL_SCRIPTS = ['preinstall', 'install', 'postinstall'] as const;

export interface PeerChange {
  name: string;
  from?: string;
  to?: string;
}

export interface PeerCheck {
  name: string;
  range: string;
  optional: boolean;
  installed?: string;
  /** `undefined` si el peer no está instalado o el rango no es semver. */
  satisfied?: boolean;
}

export interface ManifestChecks {
  /** Scripts de instalación que la candidata tiene y la actual no. */
  newInstallScripts: string[];
  peerChanges: PeerChange[];
  peers: PeerCheck[];
  engines: {
    from?: string;
    to?: string;
    /** Si la versión de Node del proyecto cumple `engines.node` de la candidata. */
    satisfiesProjectNode?: boolean;
  };
}

/**
 * Compara la versión instalada con la candidata.
 * Si no hay manifiesto de la actual (versión retirada del registro), todos los scripts de la candidata cuentan como nuevos.
 */
export function compareManifests(
  current: VersionManifest | undefined,
  candidate: VersionManifest,
  installedVersionOf: (name: string) => string | undefined,
  projectNodeVersion?: string,
): ManifestChecks {
  const newInstallScripts = INSTALL_SCRIPTS.filter((s) => candidate.scripts?.[s] && !current?.scripts?.[s]);

  const before = current?.peerDependencies ?? {};
  const after = candidate.peerDependencies ?? {};
  const peerChanges: PeerChange[] = [];
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) {
    if (before[name] !== after[name]) peerChanges.push({ name, from: before[name], to: after[name] });
  }
  peerChanges.sort((a, b) => a.name.localeCompare(b.name));

  const peers: PeerCheck[] = Object.entries(after)
    .map(([name, range]) => {
      const installed = installedVersionOf(name);
      const optional = candidate.peerDependenciesMeta?.[name]?.optional === true;
      const satisfied = installed && semver.validRange(range) !== null ? semver.satisfies(installed, range) : undefined;
      return { name, range, optional, installed, satisfied };
    })
    .sort((a, b) => a.name.localeCompare(b.name));

  const to = candidate.engines?.node;
  const node = projectNodeVersion ? semver.coerce(projectNodeVersion)?.version : undefined;
  const satisfiesProjectNode = to && node && semver.validRange(to) !== null ? semver.satisfies(node, to) : undefined;

  return {
    newInstallScripts,
    peerChanges,
    peers,
    engines: { from: current?.engines?.node, to, satisfiesProjectNode },
  };
}
