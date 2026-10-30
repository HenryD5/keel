import * as vscode from 'vscode';
import { manifestFindings, type ManifestFinding } from '../core/editor/manifestFindings';
import type { Severity } from '../core/audit/types';
import type { ScanResult } from '../core/scan';

const DEBOUNCE_MS = 180;

export interface EditorScan {
  folder: vscode.Uri;
  result: ScanResult;
}

/** Mantiene los diagnósticos del package.json del último proyecto escaneado. */
export class ManifestDiagnostics implements vscode.Disposable {
  readonly collection = vscode.languages.createDiagnosticCollection('keel');
  private scan: EditorScan | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private readonly changeSubscription: vscode.Disposable;

  constructor() {
    this.changeSubscription = vscode.workspace.onDidChangeTextDocument(({ document }) => {
      if (!this.scan || document.uri.toString() !== this.manifestUri().toString()) return;
      if (this.timer) clearTimeout(this.timer);
      this.timer = setTimeout(() => this.publish(document.getText()), DEBOUNCE_MS);
    });
  }

  async update(scan: EditorScan | undefined): Promise<void> {
    this.scan = scan;
    if (this.timer) clearTimeout(this.timer);
    this.collection.clear();
    if (!scan) return;
    const uri = this.manifestUri();
    const open = vscode.workspace.textDocuments.find((document) => document.uri.toString() === uri.toString());
    const text = open?.getText() ?? new TextDecoder().decode(await vscode.workspace.fs.readFile(uri));
    this.publish(text);
  }

  findings(document: vscode.TextDocument): ManifestFinding[] {
    if (!this.scan || document.uri.toString() !== this.manifestUri().toString()) return [];
    return manifestFindings(document.getText(), this.scan.result);
  }

  currentScan(): EditorScan | undefined {
    return this.scan;
  }

  private publish(text: string): void {
    if (!this.scan) return;
    const diagnostics = manifestFindings(text, this.scan.result).map(toDiagnostic);
    this.collection.set(this.manifestUri(), diagnostics);
  }

  private manifestUri(): vscode.Uri {
    return vscode.Uri.joinPath(this.scan!.folder, 'package.json');
  }

  dispose(): void {
    if (this.timer) clearTimeout(this.timer);
    this.changeSubscription.dispose();
    this.collection.dispose();
  }
}

function toDiagnostic(finding: ManifestFinding): vscode.Diagnostic {
  const packages = finding.pkg.map((pkg) => `${pkg.name}@${pkg.installed}`).join(', ');
  const severities = unique(finding.pkg.map((pkg) => severityLabel(pkg.severity))).join(', ');
  const recommendations = unique(
    finding.pkg.map((pkg) => pkg.resolution?.recommended?.version).filter((version): version is string => Boolean(version)),
  );
  const recommended = recommendations.length > 0
    ? vscode.l10n.t('Recommended: {0}.', recommendations.join(', '))
    : vscode.l10n.t('No safe version is currently recommended.');
  const diagnostic = new vscode.Diagnostic(
    new vscode.Range(finding.line, finding.startCharacter, finding.line, finding.endCharacter),
    vscode.l10n.t('{0} has {1} severity vulnerabilities. {2}', packages, severities, recommended),
    diagnosticSeverity(finding.severity),
  );
  diagnostic.source = 'Keel';
  return diagnostic;
}

function diagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  if (severity === 'critical' || severity === 'high') return vscode.DiagnosticSeverity.Error;
  if (severity === 'moderate') return vscode.DiagnosticSeverity.Warning;
  return vscode.DiagnosticSeverity.Information;
}

function severityLabel(severity: Severity): string {
  const labels: Record<Severity, string> = {
    critical: vscode.l10n.t('critical'),
    high: vscode.l10n.t('high'),
    moderate: vscode.l10n.t('moderate'),
    low: vscode.l10n.t('low'),
    info: vscode.l10n.t('info'),
  };
  return labels[severity];
}

function unique<T>(items: T[]): T[] {
  return [...new Set(items)];
}
