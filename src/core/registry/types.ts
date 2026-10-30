// Subconjunto del documento de paquete (packument) de registry.npmjs.org que usa Keel.

export interface VersionManifest {
  name: string;
  version: string;
  deprecated?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  engines?: Record<string, string>;
}

export interface Packument {
  name: string;
  'dist-tags': Record<string, string>;
  repository?: string | { type?: string; url?: string; directory?: string };
  /** Fecha ISO de publicación por versión, más `created` y `modified`. */
  time: Record<string, string>;
  versions: Record<string, VersionManifest>;
}
