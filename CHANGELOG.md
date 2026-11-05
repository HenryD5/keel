# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-11-05

### Added

- When a major upgrade is required, the package detail explains why the latest version of the installed line is not recommended (for example, vitest 3.2.7), listing the advisories, CVEs and ranges that still affect it; the results row names that version too.
- A link to the package's OSV page next to Snyk.
- When fixing everything requires a major upgrade, the package detail offers the version of the installed line that leaves the fewest vulnerabilities ("Upgrade to 5.4.21 without leaving 5.x"), showing how many it fixes and which CVEs stay open. If no version in the line improves anything (as with vitest 3.2.7), it says so. The CLI accepts `--choice name=line`.

### Changed

- The Snyk link opens the package page with all its versions instead of a single version.
- Borders and radio buttons use neutral colors instead of the theme's panel and focus colors, which in some themes made unselected options look selected.
- The review screen shows the selected application method clearly: a check mark and "Selected" label on the chosen card, the recommended method first, and plainer titles.

## [0.4.0] - 2026-11-05

### Added

- **Compare with a report** screen in the Keel panel: paste or load the findings from another scanner, preview how each one will be compared (exact by CVE/GHSA, by type, or not recognized), see them grouped as open, not checked and fixed, and jump to fixing the open packages.
- The package detail lists each advisory with its CVE code (from OSV aliases), GHSA, CWEs and affected range; scan results in the CLI JSON include `cves` too.

### Changed

- The command is now **Keel: Compare with a Vulnerability Report** and opens the new panel screen instead of a Markdown document; the Markdown report is still available with **Copy report**.

## [0.3.0] - 2026-11-05

### Added

- **Keel: Verify Vulnerability List** command and `keel-npm verify` check an external vulnerability list (CVE/GHSA codes, report titles, or both, one per line) against the current project. Codes are resolved through OSV (following CVE → GHSA aliases) and compared with the installed lockfile versions and `npm audit`; title-only entries are matched by vulnerability type (CWE) against the advisories that remain. In VS Code the list comes from the clipboard, a file, or the active editor, and the result opens as Markdown.

## [0.2.0] - 2026-10-30

### Fixed

- Pin planned versions by default in the extension and CLI, verify installed lockfile versions after npm install, and report the versions actually installed.
- Make `--no-validate` reliably disable CLI validation through the standard argument parser.

### Added

- Ship the repository's `keel-npm` CLI and a generic agent skill for approval-bound npm vulnerability fixes.
- Optionally run configured project test and build scripts after applying, with trusted-workspace enforcement and skipped missing scripts.
- Check package-lock registry hosts during scans and applies without exposing npm credentials.
- Offer an explicit rollback after failed apply or validation steps, with the command output tail shown in the webview.
- Discover and remember npm projects nested up to three levels, with a project-folder selector.
- Offer reviewed removal plans for unused direct vulnerable dependencies, guarded by scripts and root config references.
- Add apply reports and deterministic branch/PR creation with strict git and gh command validation.
- Fix rollback availability for rejected validation commands, rescan stale kept changes, and avoid duplicate lockfile v2 registry findings.

## [0.1.0] - 2026-10-30

### Added

- Scan npm projects with `npm audit` and recommend the minimum safe version outside the configured quarantine period.
- Cross-check candidates with OSV or Snyk and discard versions associated with malware advisories.
- Add a Keel icon to the activity bar with quick actions for scanning, the Snyk token, and the command log.
- Link each package's detail view to its public Snyk page.
- Show upgrade impact from release notes and text-based import usage in the workspace.
- Review findings, package details, risk signals, version choices, diffs, and commands in a VS Code webview.
- Apply approved changes with either npm's compatible fix flow or exact direct dependencies plus transitive `overrides`, without `--force`.
- Display vulnerability diagnostics and recommended-version hovers in `package.json`.
- Use the extension and webview in English or Spanish.

[0.1.0]: https://github.com/HenryD5/keel/releases/tag/v0.1.0
