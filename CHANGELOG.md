# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
