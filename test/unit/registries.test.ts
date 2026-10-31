import { describe, expect, it } from 'vitest';
import { allowedHosts, findDisallowedRegistries, newRegistryFindings } from '../../src/core/audit/registries';

describe('lockfile registries', () => {
  it('collects registry, scope, auth and configured hosts without tokens', () => {
    const token = 'super-secret';
    const hosts = allowedHosts(`registry=https://one.test/\n@scope:registry=https://two.test/x\n//auth.test/:_authToken=${token}\n# registry=https://ignored.test`, 'https://configured.test/');
    expect([...hosts]).toEqual(expect.arrayContaining(['registry.npmjs.org', 'one.test', 'two.test', 'auth.test', 'configured.test']));
    expect(JSON.stringify([...hosts])).not.toContain(token);
  });

  it('flags http, git and unknown hosts, but skips links and files', () => {
    const lock = JSON.stringify({ packages: {
      'node_modules/a': { name: 'a', resolved: 'http://registry.npmjs.org/a.tgz' },
      'node_modules/b': { name: 'b', resolved: 'https://evil.test/u:p/b.tgz' },
      'node_modules/c': { name: 'c', resolved: 'git+https://github.com/x/y.git' },
      'node_modules/d': { name: 'd', resolved: 'https://evil.test/d', link: true },
      'node_modules/e': { name: 'e', resolved: 'file:../e' },
    }});
    const result = findDisallowedRegistries(lock, allowedHosts(''));
    expect(result).toEqual([
      { package: 'a', host: 'registry.npmjs.org', reason: 'insecure-http' },
      { package: 'b', host: 'evil.test', reason: 'unapproved-host' },
      { package: 'c', host: 'github.com', reason: 'git-url' },
    ]);
    expect(JSON.stringify(result)).not.toContain('u:p');
  });

  it('walks v1 dependencies, tolerates malformed JSON and compares new findings', () => {
    const text = JSON.stringify({ dependencies: { a: { resolved: 'https://old.test/a', dependencies: { b: { resolved: 'https://new.test/b' } } } } });
    const all = findDisallowedRegistries(text, allowedHosts(''));
    expect(all.map((x) => x.package)).toEqual(['a', 'b']);
    expect(findDisallowedRegistries('{', allowedHosts(''))).toEqual([]);
    expect(newRegistryFindings([all[0]!], all)).toEqual([all[1]]);
  });

  it('does not duplicate v2 findings and reads git URLs from v1 version', () => {
    const v2 = JSON.stringify({ packages: { 'node_modules/a': { name: 'a', resolved: 'https://evil.test/a' } }, dependencies: { a: { resolved: 'https://evil.test/a' } } });
    expect(findDisallowedRegistries(v2, allowedHosts(''))).toHaveLength(1);
    const v1 = JSON.stringify({ dependencies: { gitdep: { version: 'git+https://github.com/acme/pkg.git' } } });
    expect(findDisallowedRegistries(v1, allowedHosts(''))).toEqual([{ package: 'gitdep', host: 'github.com', reason: 'git-url' }]);
  });
});
