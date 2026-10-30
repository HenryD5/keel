// Lectura de package-lock.json v2/v3 (sección `packages`).

export type DepType = 'prod' | 'dev' | 'optional' | 'peer';

const DEP_FIELDS: ReadonlyArray<[field: string, type: DepType]> = [
  ['dependencies', 'prod'],
  ['devDependencies', 'dev'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
];

export interface LockPackage {
  /** Ruta en el lockfile: '' para la raíz, `node_modules/x`, `node_modules/a/node_modules/x`... */
  path: string;
  name: string;
  version?: string;
  dev: boolean;
  optional: boolean;
  link: boolean;
  /** Dependencias declaradas por este paquete: nombre → rango y tipo. */
  deps: Map<string, { range: string; type: DepType }>;
}

export interface Lockfile {
  lockfileVersion: number;
  packages: Map<string, LockPackage>;
}

export class LockfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LockfileError';
  }
}

export function parseLockfile(text: string): Lockfile {
  let data: any;
  try {
    data = JSON.parse(text);
  } catch {
    throw new LockfileError('package-lock.json is not valid JSON.');
  }
  const version = data?.lockfileVersion;
  if (typeof version !== 'number' || version < 2 || typeof data.packages !== 'object' || data.packages === null) {
    throw new LockfileError('Unsupported package-lock.json (lockfileVersion 2 or 3 required). Run npm install with npm 7 or later.');
  }

  const packages = new Map<string, LockPackage>();
  for (const [path, raw] of Object.entries<any>(data.packages)) {
    const deps = new Map<string, { range: string; type: DepType }>();
    for (const [field, type] of DEP_FIELDS) {
      // En la raíz, devDependencies sí está; en el resto, npm no la guarda.
      for (const [dep, range] of Object.entries<string>(raw?.[field] ?? {})) {
        if (!deps.has(dep)) deps.set(dep, { range, type });
      }
    }
    packages.set(path, {
      path,
      // Fuera de node_modules (raíz y workspaces) el nombre real está en el propio paquete.
      name: path.includes('node_modules/') ? nameFromPath(path) : (raw?.name ?? nameFromPath(path)),
      version: typeof raw?.version === 'string' ? raw.version : undefined,
      dev: raw?.dev === true,
      optional: raw?.optional === true,
      link: raw?.link === true,
      deps,
    });
  }
  return { lockfileVersion: version, packages };
}

/** `node_modules/a/node_modules/@s/b` → `@s/b`. Para rutas de workspace devuelve el último segmento. */
export function nameFromPath(path: string): string {
  const idx = path.lastIndexOf('node_modules/');
  const tail = idx >= 0 ? path.slice(idx + 'node_modules/'.length) : path.split('/').pop() ?? path;
  return tail;
}

/** Carpeta desde la que se sigue buscando hacia arriba: `node_modules/a/node_modules/b` → `node_modules/a`. */
function parentLocation(path: string): string {
  const idx = path.lastIndexOf('/node_modules/');
  return idx >= 0 ? path.slice(0, idx) : '';
}

/** Resuelve `dep` desde el paquete en `fromPath` siguiendo el algoritmo de Node (sube por las carpetas node_modules). */
export function resolveDependency(lock: Lockfile, fromPath: string, dep: string): string | undefined {
  let base = fromPath;
  for (;;) {
    const candidate = base === '' ? `node_modules/${dep}` : `${base}/node_modules/${dep}`;
    if (lock.packages.has(candidate)) return candidate;
    if (base === '') return undefined;
    base = parentLocation(base);
  }
}

export interface Dependent {
  path: string;
  name: string;
  /** Rango con el que este paquete pide la dependencia. */
  range: string;
  type: DepType;
}

/** Paquetes del lockfile que resuelven a `nodePath` (incluida la raíz, con path ''). */
export function dependentsOf(lock: Lockfile, nodePath: string): Dependent[] {
  const name = nameFromPath(nodePath);
  const out: Dependent[] = [];
  for (const pkg of lock.packages.values()) {
    if (pkg.link) continue;
    const dep = pkg.deps.get(name);
    if (dep && resolveDependency(lock, pkg.path, name) === nodePath) {
      out.push({ path: pkg.path, name: pkg.name, range: dep.range, type: dep.type });
    }
  }
  return out;
}

/** Dependencias directas de la raíz por las que se llega a `nodePath`. */
export function topLevelAncestors(lock: Lockfile, nodePath: string): string[] {
  const result = new Set<string>();
  const visited = new Set<string>([nodePath]);
  const queue = [nodePath];
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const d of dependentsOf(lock, current)) {
      if (d.path === '') {
        if (current !== nodePath) result.add(nameFromPath(current));
      } else if (!visited.has(d.path)) {
        visited.add(d.path);
        queue.push(d.path);
      }
    }
  }
  return [...result].sort();
}
