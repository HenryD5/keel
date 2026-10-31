---
name: keel-fix-vulnerabilities
description: Safely fix npm vulnerabilities and respond to npm audit results with reviewed minimum-safe dependency changes.
---

# Fix npm vulnerabilities with Keel

Run `npx keel-npm scan --json`. Present affected packages, minimum safe versions, and risk. Start from `defaultSelection`, but never choose versions for the user.

Never run `npm audit fix --force`, `npm update`, `npm-check-updates -u`, use `--legacy-peer-deps`, or stage with `git add .`. Items that may break or have a reference discrepancy require explicit user approval.

Run `npx keel-npm plan --select <packages> --json`, show the diff and skipped items, and ask the user to approve that exact plan. Run `npx keel-npm apply --plan <planId> --select <packages> --json` only after approval, with the same selection and choices. Versions are pinned by default. Never use `--keep-range` unless the user explicitly asks to preserve dependency ranges; if they do, use it for both plan and apply and explain that npm may install a newer version within the range. Apply writes the approved manifest and runs `npm install`; it never runs `npm audit fix`. Treat the post-apply rescan and installed lockfile versions as the source of truth. Revert is available only after a failed apply and refuses if either npm project file changed afterward.

If apply fails, show the error and ask whether to run `npx keel-npm revert`. Do not edit tests or code to make validation pass.

Finish with `npx keel-npm report --format markdown` and state what remains pending. Never claim success for skipped steps.

Only commit, push, or open a pull request when the user asks. Stage only `package.json` and `package-lock.json`. A pull request may use the report as its body.
