import * as vscode from 'vscode';
import type { Severity } from '../core/audit/types';
import type { PackageReport } from '../core/scan';
import type { ManifestDiagnostics } from './diagnostics';

/** Detalle seguro de la vulnerabilidad al pasar sobre una dependencia marcada. */
export class ManifestHoverProvider implements vscode.HoverProvider {
  constructor(private readonly diagnostics: ManifestDiagnostics) {}

  provideHover(document: vscode.TextDocument, position: vscode.Position): vscode.Hover | undefined {
    const finding = this.diagnostics.findings(document).find(
      (item) => item.line === position.line && position.character >= item.startCharacter && position.character <= item.endCharacter,
    );
    if (!finding) return undefined;

    const markdown = new vscode.MarkdownString();
    markdown.isTrusted = false;
    markdown.appendMarkdown('**Keel**\n\n');
    finding.pkg.forEach((pkg, index) => {
      if (index > 0) markdown.appendMarkdown('\n\n---\n\n');
      appendPackage(markdown, pkg, finding.name);
    });
    return new vscode.Hover(
      markdown,
      new vscode.Range(finding.line, finding.startCharacter, finding.line, finding.endCharacter),
    );
  }
}

function appendPackage(markdown: vscode.MarkdownString, pkg: PackageReport, manifestName: string): void {
  markdown.appendMarkdown('**');
  markdown.appendText(pkg.name);
  markdown.appendMarkdown('**');
  if (pkg.name !== manifestName) {
    markdown.appendMarkdown(' — ');
    markdown.appendText(vscode.l10n.t('via {0}', manifestName));
  }
  markdown.appendMarkdown('\n\n');

  const target = pkg.resolution?.recommended?.version;
  markdown.appendText(target
    ? vscode.l10n.t('Installed {0} → recommended {1}', pkg.installed, target)
    : vscode.l10n.t('Installed {0} → no safe version recommended', pkg.installed));
  markdown.appendMarkdown('  \n');
  markdown.appendText(formatCounts(pkg.counts));
  markdown.appendMarkdown('  \n');
  markdown.appendText(auditFixText(pkg));
  markdown.appendMarkdown('  \n');
  markdown.appendText(quarantineText(pkg));
}

function formatCounts(counts: Record<Severity, number>): string {
  const labels: Record<Severity, string> = {
    critical: vscode.l10n.t('{0} critical', counts.critical),
    high: vscode.l10n.t('{0} high', counts.high),
    moderate: vscode.l10n.t('{0} moderate', counts.moderate),
    low: vscode.l10n.t('{0} low', counts.low),
    info: vscode.l10n.t('{0} info', counts.info),
  };
  const parts = (['critical', 'high', 'moderate', 'low', 'info'] as const).filter((severity) => counts[severity] > 0).map((severity) => labels[severity]);
  return parts.join(' · ') || vscode.l10n.t('No vulnerabilities');
}

function auditFixText(pkg: PackageReport): string {
  if (pkg.auditFix.kind === 'audit-fix') return vscode.l10n.t('npm audit fix can fix it without --force.');
  if (pkg.auditFix.kind === 'force') return vscode.l10n.t('npm would require --force.');
  return vscode.l10n.t('npm audit fix behavior could not be predicted.');
}

function quarantineText(pkg: PackageReport): string {
  const resolution = pkg.resolution;
  if (!resolution) return vscode.l10n.t('Quarantine status unavailable.');
  if (resolution.status === 'quarantine-only' && resolution.waitingFor) {
    return vscode.l10n.t('In quarantine until {0}.', resolution.waitingFor.waitUntil?.slice(0, 10) ?? '?');
  }
  if (resolution.quarantineBypassed) return vscode.l10n.t('Quarantine bypassed because the vulnerability is critical.');
  return vscode.l10n.t('Recommended version is outside quarantine.');
}
