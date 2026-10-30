import { findNodeAtLocation, parseTree, type Node } from 'jsonc-parser';
import type { Severity } from '../audit/types';
import { SEVERITY_ORDER } from '../audit/types';
import type { PackageReport, ScanResult } from '../scan';

export interface ManifestFinding {
  /** Nombre de la dependencia cuya clave está marcada en el manifiesto. */
  name: string;
  line: number;
  startCharacter: number;
  endCharacter: number;
  offset: number;
  length: number;
  severity: Severity;
  pkg: PackageReport[];
  /** Paquetes transitivos vulnerables que llegan por esta dependencia directa. */
  via?: string[];
}

const SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'] as const;

/** Localiza y agrupa los paquetes vulnerables sobre claves reales de package.json. */
export function manifestFindings(text: string, result: ScanResult): ManifestFinding[] {
  const root = parseTree(text);
  if (!root) return [];

  const grouped = new Map<string, { node: Node; name: string; packages: PackageReport[]; via: Set<string> }>();
  const add = (name: string, pkg: PackageReport, transitively: boolean) => {
    const node = dependencyKey(root, name);
    if (!node) return;
    const key = `${node.offset}:${node.length}`;
    let group = grouped.get(key);
    if (!group) {
      group = { node, name, packages: [], via: new Set() };
      grouped.set(key, group);
    }
    if (!group.packages.some((item) => item.name === pkg.name)) group.packages.push(pkg);
    if (transitively) group.via.add(pkg.name);
  };

  for (const pkg of result.packages) {
    if (pkg.direct) add(pkg.name, pkg, false);
    else for (const name of pkg.viaTopLevel) add(name, pkg, true);
  }

  return [...grouped.values()]
    .map(({ node, name, packages, via }) => {
      const offset = node.offset + 1; // Se excluyen las comillas de la clave.
      const { line, character } = positionAt(text, offset);
      return {
        name,
        line,
        startCharacter: character,
        endCharacter: character + name.length,
        offset,
        length: name.length,
        severity: packages.reduce((max, pkg) => maxSeverity(max, pkg.severity), 'info' as Severity),
        pkg: packages,
        ...(via.size > 0 ? { via: [...via].sort() } : {}),
      };
    })
    .sort((a, b) => a.offset - b.offset);
}

function dependencyKey(root: Node, name: string): Node | undefined {
  for (const section of SECTIONS) {
    const value = findNodeAtLocation(root, [section, name]);
    const property = value?.parent;
    const key = property?.children?.[0];
    if (key?.type === 'string') return key;
  }
  return undefined;
}

function positionAt(text: string, offset: number): { line: number; character: number } {
  let line = 0;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (text.charCodeAt(i) === 10) {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, character: offset - lineStart };
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b;
}
