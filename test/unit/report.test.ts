import { describe, expect, it } from 'vitest';
import { buildApplyReport } from '../../src/core/report';

describe('apply report', () => {
  it('separates a failed step from pending vulnerabilities and unconfirmed updates', () => {
    const report = buildApplyReport({ language: 'en', updated: [], pending: [], failedStep: { name: 'npm install', reason: 'exit 1' } });
    expect(report).toContain('## Failed step');
    expect(report).toContain('**npm install**: exit 1');
    expect(report).not.toContain('## Pending vulnerabilities');
    expect(report).not.toContain('## Updated packages');
  });

  it('reports measured after counts and fresh pending reasons', () => {
    const report = buildApplyReport({ language: 'en', after: { high: 1 }, pending: [{ name: 'left-pad', reason: 'still vulnerable after apply' }] });
    expect(report).toContain('## Vulnerabilities after');
    expect(report).toContain('**left-pad**: still vulnerable after apply');
  });

  it('reports installed rather than planned versions and range mismatches', () => {
    const report = buildApplyReport({ language: 'en', updated: [{ name: 'axios', from: '1.18.0', to: '1.21.0' }], versionWarnings: [{ name: 'axios', planned: '1.20.0', installed: '1.21.0' }] });
    expect(report).toContain('1.18.0 → 1.21.0');
    expect(report).toContain('planned 1.20.0, installed 1.21.0');
  });
});
