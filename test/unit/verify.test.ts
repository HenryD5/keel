import { describe, expect, it, vi } from 'vitest';
import { parseAudit } from '../../src/core/audit/parseAudit';
import { parseLockfile } from '../../src/core/audit/lockfile';
import type { OsvVuln } from '../../src/core/reference/osv';
import { fetchOsvVuln } from '../../src/core/reference/osv';
import { categoryOf } from '../../src/core/verify/categories';
import { formatVerifyResult } from '../../src/core/verify/format';
import { parseVulnerabilityList, verifyList } from '../../src/core/verify/verify';
import { fixtureText } from './helpers';

const braces = (JSON.parse(fixtureText('osv/braces.json')) as { vulns: OsvVuln[] }).vulns;
const bracesGhsa = braces.find((v) => v.id === 'GHSA-grv7-fg5c-xmjg')!;
const cveRecord: OsvVuln = { id: 'CVE-2024-4068', aliases: ['GHSA-grv7-fg5c-xmjg'], affected: [{ ranges: [{ type: 'GIT', events: [{ introduced: '0' }] }] }] };

function lockWith(versions: Record<string, string>) {
  const packages: Record<string, unknown> = { '': { name: 'app' } };
  for (const [path, version] of Object.entries(versions)) packages[path] = { version };
  return parseLockfile(JSON.stringify({ lockfileVersion: 3, packages }));
}

const emptyAudit = parseAudit(JSON.stringify({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } }));
const sampleAudit = parseAudit(fixtureText('audit/sample.json'));
const getVuln = vi.fn(async (id: string) => ({ 'CVE-2024-4068': cveRecord, 'GHSA-grv7-fg5c-xmjg': { ...bracesGhsa, database_specific: { cwe_ids: ['CWE-400', 'CWE-1050'] } } } as Record<string, OsvVuln>)[id]);

describe('parseVulnerabilityList', () => {
  it('extrae códigos y títulos, agrupa repetidas e ignora vacías y comentarios', () => {
    const items = parseVulnerabilityList('Prototype Pollution\n\n# nota\nprototype pollution\ncve-2024-4068, Asymmetric denial of service\tGHSA-GRV7-FG5C-XMJG\n');
    expect(items).toEqual([
      { lines: [1, 4], ids: [], title: 'Prototype Pollution' },
      { lines: [5], ids: ['CVE-2024-4068', 'GHSA-grv7-fg5c-xmjg'], title: 'Asymmetric denial of service' },
    ]);
  });
});

describe('categoryOf', () => {
  it('reconoce los tipos del reporte, con los más específicos primero', () => {
    expect(categoryOf('Asymmetric denial of service - ReDoS')?.key).toBe('redos');
    expect(categoryOf('Lack of data validation - Path Traversal')?.key).toBe('path-traversal');
    expect(categoryOf('Lack of data validation')?.key).toBe('data-validation');
    expect(categoryOf('Reflected cross-site scripting (XSS)')?.key).toBe('xss');
    expect(categoryOf('Cross-site request forgery')?.key).toBe('csrf');
    expect(categoryOf('Improper authorization control for web services')?.key).toBe('authorization');
    expect(categoryOf('Inadequate file size control')?.key).toBe('file-size');
    expect(categoryOf('Insecure functionality')).toBeUndefined();
  });
});

describe('verifyList', () => {
  it('un CVE sigue el alias GHSA y marca la versión instalada vulnerable con su corrección', async () => {
    const result = await verifyList(parseVulnerabilityList('CVE-2024-4068'), { audit: emptyAudit, lock: lockWith({ 'node_modules/braces': '3.0.2' }), getVuln });
    const [item] = result.items;
    expect(item!.status).toBe('vulnerable');
    expect(item!.checks[0]!.vulnerable).toEqual([{ package: 'braces', version: '3.0.2', path: 'node_modules/braces', fixedIn: '3.0.3' }]);
    expect(result.allResolved).toBe(false);
  });

  it('marca corregido, no instalado y desconocido', async () => {
    const fixed = await verifyList(parseVulnerabilityList('CVE-2024-4068'), { audit: emptyAudit, lock: lockWith({ 'node_modules/braces': '3.0.3' }), getVuln });
    expect(fixed.items[0]!.status).toBe('fixed');
    expect(fixed.allResolved).toBe(true);
    const gone = await verifyList(parseVulnerabilityList('GHSA-grv7-fg5c-xmjg'), { audit: emptyAudit, lock: lockWith({}), getVuln });
    expect(gone.items[0]!.status).toBe('not-installed');
    const unknown = await verifyList(parseVulnerabilityList('CVE-1999-0001'), { audit: emptyAudit, lock: lockWith({}), getVuln });
    expect(unknown.items[0]!.outcome).toBe('unverified');
  });

  it('un código que npm audit todavía reporta sigue pendiente', async () => {
    const result = await verifyList(parseVulnerabilityList('GHSA-vh66-26gq-q6x8'), { audit: sampleAudit, lock: lockWith({}), getVuln: async () => undefined });
    expect(result.items[0]!.status).toBe('vulnerable');
  });

  it('comprueba si el código encaja con el título', async () => {
    const ok = await verifyList(parseVulnerabilityList('CVE-2024-4068 Asymmetric denial of service'), { audit: emptyAudit, lock: lockWith({}), getVuln });
    expect(ok.items[0]!.titleMatches).toBe(true);
    const wrong = await verifyList(parseVulnerabilityList('CVE-2024-4068 Reflected cross-site scripting (XSS)'), { audit: emptyAudit, lock: lockWith({}), getVuln });
    expect(wrong.items[0]!.titleMatches).toBe(false);
  });

  it('un título sin código busca avisos restantes del mismo tipo', async () => {
    const items = parseVulnerabilityList('Prototype Pollution\nProtoType pollution\nHTTP request smuggling\nInsecure functionality');
    const result = await verifyList(items, { audit: sampleAudit, lock: lockWith({}), getVuln });
    const [proto, smuggling, unmapped] = result.items;
    expect(proto!.status).toBe('remaining');
    expect(proto!.candidates.every((c) => c.package === 'axios')).toBe(true);
    expect(proto!.lines).toEqual([1, 2]);
    expect(smuggling!.status).toBe('no-remaining');
    expect(unmapped!.status).toBe('unmapped');
    expect(result.totals).toMatchObject({ lines: 4, distinct: 3, pending: 2, resolved: 1, unverified: 1 });
    const text = formatVerifyResult(result, 'es');
    expect(text).toContain('Aún no está todo corregido');
    expect(text).toContain('×2');
  });
});

describe('fetchOsvVuln', () => {
  it('rechaza IDs inválidos y trata 404 como inexistente', async () => {
    await expect(fetchOsvVuln('../x', async () => null)).rejects.toThrow();
    expect(await fetchOsvVuln('CVE-2024-4068', async () => null)).toBeUndefined();
  });
});
