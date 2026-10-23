# Changelog

## 1.0.0 — 2026-10-23

- Added dependency-free Node2Shell (CVE-2026-111497) version assessment with
  branch-specific fixes for Node.js 22, 24, and 26.
- Added offline reported-version and collector-inventory inputs, alongside
  conservative public website metadata checks.
- Added an optional local runtime collector with limited metadata collection.
- Added CSV, structured JSON, and branded offline HTML reports with explicit
  uncertainty, source provenance, and run-completeness information.
- Added report overwrite protection, optional finding exit codes, local tests,
  cross-platform Python CI, and operational/reference documentation.
- Adopted the CompleteTech LLC AGPL-3.0 / commercial licensing model used by
  php2shell-check.
