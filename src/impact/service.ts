import * as vscode from 'vscode';
import { extractBreakingLines } from '../core/impact/breaking';
import { getChangelog, type ChangelogCache, type GetJson, type Release } from '../core/impact/changelog';
import { findUsages, SOURCE_EXTENSIONS } from '../core/impact/imports';
import { removalBlockReason } from '../core/apply/removal';
import type { PackageReport } from '../core/scan';
import type { Logger } from '../infra/log';
import type { ChangelogView, Lang, UsagesView } from '../webview/protocol';
import { summarizeWithLm } from './lmSummary';

const MAX_FILES = 5_000;
const MAX_FILE_BYTES = 1_000_000;
const READ_CONCURRENCY = 16;

/** Impacto de actualizar un paquete: dónde se usa, changelog y resumen. Caché en memoria por escaneo. */
export class ImpactService {
  private readonly usageCache = new Map<string, Promise<UsagesView>>();
  private readonly summaryCache = new Map<string, Promise<ChangelogView>>();

  constructor(
    private readonly folder: vscode.Uri,
    private readonly log: Logger,
    private readonly getJson: GetJson,
    private readonly changelogCache: ChangelogCache,
  ) {}

  usages(name: string): Promise<UsagesView> {
    let pending = this.usageCache.get(name);
    if (!pending) {
      pending = this.findUsages(name);
      pending.catch(() => this.usageCache.delete(name));
      this.usageCache.set(name, pending);
    }
    return pending;
  }

  changelog(pkg: PackageReport, to: string, lang: Lang): Promise<ChangelogView> {
    const key = `${pkg.name}@${pkg.installed}→${to}:${lang}`;
    let pending = this.summaryCache.get(key);
    if (!pending) {
      pending = this.buildChangelog(pkg, to, lang);
      pending.catch(() => this.summaryCache.delete(key));
      this.summaryCache.set(key, pending);
    }
    return pending;
  }

  private async findUsages(name: string): Promise<UsagesView> {
    const pattern = new vscode.RelativePattern(this.folder, `**/*.{${SOURCE_EXTENSIONS.join(',')}}`);
    const uris = await vscode.workspace.findFiles(pattern, '**/node_modules/**', MAX_FILES + 1);
    const truncated = uris.length > MAX_FILES;
    const files = uris.slice(0, MAX_FILES);
    const usages: UsagesView['usages'] = [];
    let next = 0;
    let filesWithUsage = 0;

    const worker = async () => {
      while (next < files.length) {
        const uri = files[next++]!;
        try {
          const stat = await vscode.workspace.fs.stat(uri);
          if (stat.size > MAX_FILE_BYTES) continue;
          const text = new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
          if (!text.includes(name)) continue;
          const found = findUsages(text, name);
          if (found.length === 0) continue;
          filesWithUsage++;
          const path = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, '/');
          for (const u of found) usages.push({ path, line: u.line, symbol: u.symbol, kind: u.kind });
        } catch {
          // Archivo ilegible o borrado durante la búsqueda: se omite.
        }
      }
    };
    await Promise.all(Array.from({ length: READ_CONCURRENCY }, worker));
    usages.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
    this.log.info(`Usages of ${name}: ${usages.length} in ${filesWithUsage} files (${files.length} files searched)`);
    let removal: UsagesView['removal'];
    if (usages.length === 0 && !truncated) {
      try {
        const manifestText = new TextDecoder().decode(await vscode.workspace.fs.readFile(vscode.Uri.joinPath(this.folder, 'package.json')));
        const manifest = JSON.parse(manifestText);
        const direct = ['dependencies', 'devDependencies', 'optionalDependencies'].some((key) => typeof manifest[key]?.[name] === 'string');
        if (direct) {
          const configUris = await vscode.workspace.findFiles(new vscode.RelativePattern(this.folder, '{*.config.*,.*rc*}'), undefined, 100);
          const configs = await Promise.all(configUris.map(async (uri) => ({ path: uri.path.split('/').at(-1) ?? uri.path, text: new TextDecoder().decode(await vscode.workspace.fs.readFile(uri)) })));
          const reason = removalBlockReason(manifestText, name, [name.split('/').at(-1) ?? name], configs);
          removal = reason ? { allowed: false, reason } : { allowed: true };
        }
      } catch { /* Sin oferta si no se puede comprobar con seguridad. */ }
    }
    return { usages, files: filesWithUsage, truncated, removal };
  }

  private async buildChangelog(pkg: PackageReport, to: string, lang: Lang): Promise<ChangelogView> {
    const result = await getChangelog({
      name: pkg.name,
      repository: pkg.repository,
      from: pkg.installed,
      to,
      getJson: this.getJson,
      cache: this.changelogCache,
    });
    const view: ChangelogView = {
      url: result.url,
      releases: result.releases.map((r) => ({ version: r.version, tag: r.tag, url: r.url, publishedAt: r.publishedAt })),
      unavailable: result.unavailable,
      empty: result.empty,
      error: result.error ? githubError(result.error) : undefined,
      summary: { kind: 'none' },
    };
    if (result.releases.length === 0) return view;

    const ai = await summarizeWithLm({ name: pkg.name, from: pkg.installed, to, releases: result.releases, lang, log: this.log });
    if (ai) return { ...view, summary: { kind: 'ai', lines: ai } };
    const breaking = extractBreakingLines(result.releases);
    return { ...view, summary: breaking.length > 0 ? { kind: 'breaking', lines: breaking } : { kind: 'none' } };
  }
}

function githubError(message: string): string {
  return /HTTP (403|429)/.test(message) ? vscode.l10n.t('GitHub rate limit reached. Try again later.') : message;
}

const CACHE_KEY = 'keel.changelogCache.v1';
const CACHE_TTL_MS = 12 * 60 * 60 * 1000;
const CACHE_MAX_ENTRIES = 50;

interface StoredEntry {
  at: number;
  releases: Release[];
}

/** Caché de releases en `globalState`, para no gastar el límite de GitHub (60 peticiones por hora sin token). */
export function createChangelogCache(state: vscode.Memento, now: () => number = Date.now): ChangelogCache {
  const read = () => state.get<Record<string, StoredEntry>>(CACHE_KEY, {});
  return {
    get(key) {
      const entry = read()[key];
      return entry && now() - entry.at < CACHE_TTL_MS ? entry.releases : undefined;
    },
    set(key, releases) {
      const entries = Object.entries({ ...read(), [key]: { at: now(), releases } })
        .filter(([, e]) => now() - e.at < CACHE_TTL_MS)
        .sort(([, a], [, b]) => b.at - a.at)
        .slice(0, CACHE_MAX_ENTRIES);
      void state.update(CACHE_KEY, Object.fromEntries(entries));
    },
  };
}
