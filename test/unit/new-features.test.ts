import { describe, expect, it } from 'vitest';
import { buildRemovalPlan, removalBlockReason } from '../../src/core/apply/removal';
import { projectCandidates } from '../../src/core/projectFolders';
import { branchNameForChanges, unexpectedChanges } from '../../src/core/pullRequest';
import { buildApplyReport } from '../../src/core/report';
import { parseWebviewMessage } from '../../src/webview/protocol';

describe('project folders', () => {
  it('keeps root first, limits depth and ignores generated folders', () => {
    const file = (path: string) => ({ path, kind: 'file' as const });
    expect(projectCandidates(['package.json', 'package-lock.json', 'apps/a/package.json', 'apps/a/package-lock.json', 'a/b/c/d/package.json', 'a/b/c/d/package-lock.json', 'dist/x/package.json', 'dist/x/package-lock.json'].map(file))).toEqual(['', 'apps/a']);
  });
});

describe('dependency removal', () => {
  const manifest = '{\n  "scripts": { "lint": "eslint ." },\n  "dependencies": { "left-pad": "^1.0.0" }\n}\n';
  it('builds a reviewable diff while preserving formatting', () => {
    const plan = buildRemovalPlan(manifest, 'left-pad');
    expect(plan.removed?.[0]).toMatchObject({ name: 'left-pad', oldSpec: '^1.0.0' });
    expect(plan.newManifestText).not.toContain('left-pad');
    expect(plan.diff.some((line) => line.kind === 'del')).toBe(true);
  });
  it('blocks script and root config references', () => {
    expect(removalBlockReason(manifest, 'eslint', ['eslint'], [])).toContain('lint');
    expect(removalBlockReason(manifest, 'left-pad', [], [{ path: 'tool.config.js', text: "require('left-pad')" }])).toContain('tool.config.js');
  });
});

it('builds stable branch names from sorted changes', () => {
  expect(branchNameForChanges([{ name: 'b', from: '1', to: '2' }, { name: 'a', removed: true }])).toBe(branchNameForChanges([{ name: 'a', removed: true }, { name: 'b', from: '1', to: '2' }]));
  expect(branchNameForChanges([{ name: 'a', removed: true }])).toMatch(/^keel\/fix-[a-f0-9]{8}$/);
});

describe('pull request working tree changes', () => {
  it('allows the manifest and lockfile at the repository root', () => {
    expect(unexpectedChanges(' M package.json\nM  package-lock.json\n', '')).toEqual([]);
  });

  it('allows the project files below the repository root', () => {
    expect(unexpectedChanges(' M app/package.json\n M app/package-lock.json\n', 'app/')).toEqual([]);
  });

  it('checks both sides of renames', () => {
    expect(unexpectedChanges('R  package.json -> package-lock.json\n', '')).toEqual([]);
    expect(unexpectedChanges('R  package.json -> src/package.json\n', '')).toEqual(['src/package.json']);
  });

  it('decodes quoted paths before comparing them', () => {
    expect(unexpectedChanges(' M "app/package.json"\n M "other file.json"\n', 'app/')).toEqual(['other file.json']);
  });

  it('always rejects untracked files and reports other files', () => {
    expect(unexpectedChanges('?? app/package.json\n?? notes.txt\n M app/src/index.ts\n', 'app/')).toEqual(['app/package.json', 'notes.txt', 'app/src/index.ts']);
  });
});

it('reports only applicable sections and calls skipped validation unresolved', () => {
  const report = buildApplyReport({ language: 'en', removed: ['a'], validation: [{ script: 'test', status: 'skipped' }] });
  expect(report).toContain('Removed packages');
  expect(report).toContain('skipped');
  expect(report).toContain('remain unresolved');
  expect(report).not.toContain('Updated packages');
});

it('validates new webview messages', () => {
  expect(parseWebviewMessage({ type: 'selectProject' })).toEqual({ type: 'selectProject' });
  expect(parseWebviewMessage({ type: 'copyReport' })).toEqual({ type: 'copyReport' });
  expect(parseWebviewMessage({ type: 'createPullRequest' })).toEqual({ type: 'createPullRequest' });
  expect(parseWebviewMessage({ type: 'requestRemovalPlan', name: 'axios' })).toEqual({ type: 'requestRemovalPlan', name: 'axios' });
  expect(parseWebviewMessage({ type: 'requestRemovalPlan', name: 1 })).toBeUndefined();
});
