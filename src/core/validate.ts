import semver from 'semver';

// Nombres válidos de npm, incluidos los antiguos con mayúsculas (p. ej. JSONStream).
const PACKAGE_NAME = /^(?:@[a-zA-Z0-9][a-zA-Z0-9._~-]*\/)?[a-zA-Z0-9~-][a-zA-Z0-9._~-]*$/;
const MAX_NAME_LENGTH = 214;

// Solo versiones exactas X.Y.Z, con prerelease y build opcionales.
const EXACT_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function isValidPackageName(name: string): boolean {
  return name.length > 0 && name.length <= MAX_NAME_LENGTH && PACKAGE_NAME.test(name) && !name.startsWith('.');
}

export function isValidVersion(version: string): boolean {
  return EXACT_VERSION.test(version) && semver.valid(version) === version;
}

export function assertPackageName(name: string): string {
  if (!isValidPackageName(name)) throw new Error(`Invalid package name: ${JSON.stringify(name)}`);
  return name;
}

export function assertVersion(version: string): string {
  if (!isValidVersion(version)) throw new Error(`Invalid version: ${JSON.stringify(version)}`);
  return version;
}
