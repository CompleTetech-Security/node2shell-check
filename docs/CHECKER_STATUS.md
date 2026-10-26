# Checker family delivery status

Audit date: **2026-10-25**. This is a delivery snapshot, not an assessment of any
runtime, customer, website or production deployment. Recheck GitHub before using
these commits as current-state evidence.

## Continued delivery after the initial audit

Delivery receipt updated **2026-10-26 UTC** (October 25 in America/New_York).
The initial 48-repository audit below is historical. Its missing-adapter and
missing-repository statements are superseded by this delivery section. Two new
optional support repositories bring the current family inventory to 50.

Implemented and merged with GitHub Copilot review and passing hosted checks:

- All 17 edge checkers' actual CSV/configuration paths are reconciled in the
  [edge matrix](EDGE_ADVISORY_MATRIX.md). Fifteen separate metadata PRs add dated
  KEV fields; the two initial NetScaler tools already had dated threat metadata.
  The full pinned CISA catalog digest, CVE presence/absence and listing dates
  were checked independently. No threshold changes or target scans were made.
- The [Node matrix](NODE_ADVISORY_MATRIX.md) maps all 21 named July/October CVEs
  to separate checkers. [Optional Node metadata](NODE_METADATA.md) reports
  builtin capability shape and npm engine declarations; neither establishes
  application use, reachability, installed runtime identity or advisory exposure.
- Sharp adds npm/SBOM metadata, bounded ELF observations and lexical SVG/source
  mitigation candidates. Namespaced SBOM packages cannot impersonate unscoped
  packages. vm2 and simple-git add bounded dependency/source candidates, with
  line-ending and arrow-regex corrections. These are syntax hints, not taint
  analysis or proof of runtime behavior.
- CopyEscape adds Docker export observations and bounded shell/YAML copy-command
  candidates. Unsupported syntax emits unresolved coverage. Export input-slot
  identities do not encode absolute paths; argument order matters for comparison.
- Atlassian adds explicit local version files, evidence confidence and input
  ordinals. Files are independent observations; conflicts within a file remain
  unknown. Flowise adds allowlisted deployment/owner/package metadata and
  independent instance grouping. Unverified deployment exports remain unknown,
  including affected-range versions; `--fail-on-finding` does not flag unknowns.
- [OCI inventory](https://github.com/CompleTetech-Security/oci-runtime-inventory)
  parses bounded local archives/SBOMs without extraction or execution, preserving
  provenance and incomplete coverage. Its consumer profiles use actual checker
  input contracts and retain unverified build provenance. Docker config identity
  does not authenticate supplied layers or attest a running image.
- [Result bridge](https://github.com/CompleTetech-Security/scan-results-bridge)
  converts explicit versioned canonical/legacy reports to SARIF/NDJSON, retaining
  unknown/not_tested, completion, conflicts and observation counts. Relative
  source paths require opt-in; privacy hashes remain linkable and guessable.
- [Optional offline TUF verification](../tools/signed_rules/README.md) is merged
  in [PR #21](https://github.com/CompleTetech-Security/node2shell-check/pull/21).
  Real synthetic signatures test expiry, rotation/revocation, rollback and
  protected output separately from the standalone core. This authenticates a
  local artifact for subsequent review/release preparation; it does not install
  rules automatically or provision a hosted feed.

**Remaining:** [#13](https://github.com/CompleTetech-Security/node2shell-check/issues/13)
requires production publisher custody, an independently distributed public trust
root and an authenticated release/feed channel with recovery ownership. The
recommendation is an offline Ed25519 2-of-3 root with separate release-role keys.
No production keys or feed are provisioned. Keep the parent #2 open for that work.
Other child implementation scopes are fulfilled by the merged work and matrices;
this documentation does not assert production deployment or assessment.

Local suites on the final implementations: Node2Shell/metadata 65, optional TUF
13, Sharp 73, vm2 31, simple-git 32, CopyEscape 78, Atlassian 58, Flowise 70,
OCI 19 and bridge 13. Platform skips are reported by each suite. The two initial
NetScaler suites also pass locally (52 and 64). All 15 KEV-update suites passed
locally with 40–72 cases each. Bridge output passed five variants against the
vendored official OASIS SARIF schema. No real targets were assessed.

Copilot's hosted findings and independent CLI reviews informed fixes. The hosted
review quota was exhausted during final revisions; completed Copilot CLI reviews
provided the remaining review receipts. Review scope is recorded in each PR;
reviewers did not execute tests. Local checks, exact-head hosted checks, actual
merge-commit checks and production trust are separate evidence.

### Actual merge-commit CI receipts

Every job below completed successfully on the listed default-branch commit,
not only on its pre-merge PR head. Node2Shell has six core and six optional TUF
jobs; each other listed repository has six Linux/Windows/macOS jobs.

| Repository | Default-branch delivery commit | Hosted merge-commit checks |
| --- | --- | --- |
| [atlassian-cve-2026-21589-check](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check) | [`d729faa6d81f1e010f739d61aa6fb5355f7517f9`](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check/commit/d729faa6d81f1e010f739d61aa6fb5355f7517f9) | [6 passed](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check/actions/runs/40250003806) |
| [beyondtrust-remote-support-cve-2026-102764-check](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check) | [`221fbffbbd4347cade806f9f70a2253303f016ff`](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/commit/221fbffbbd4347cade806f9f70a2253303f016ff) | [6 passed](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/actions/runs/40249630072) |
| [copyescape-check](https://github.com/CompleTetech-Security/copyescape-check) | [`2b73e559dcc0ab5a4183008410c4eb9fd78715ab`](https://github.com/CompleTetech-Security/copyescape-check/commit/2b73e559dcc0ab5a4183008410c4eb9fd78715ab) | [6 passed](https://github.com/CompleTetech-Security/copyescape-check/actions/runs/40250065787) |
| [flowise-cve-2026-69254-check](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check) | [`4cbf661bcb148cf132b4cd38635f2bd453da2961`](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check/commit/4cbf661bcb148cf132b4cd38635f2bd453da2961) | [6 passed](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check/actions/runs/40250011163) |
| [fortimail-cve-2026-104286-check](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check) | [`9cdca2e3851d89502bdc30b7ae53b9ac0622a91c`](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/commit/9cdca2e3851d89502bdc30b7ae53b9ac0622a91c) | [6 passed](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/actions/runs/40249104350) |
| [ivanti-connect-secure-cve-2026-104935-check](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check) | [`810cd49573a6ef73b76bca28b9f62993549539c6`](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/commit/810cd49573a6ef73b76bca28b9f62993549539c6) | [6 passed](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/actions/runs/40249640225) |
| [netscaler-cve-2026-19489-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check) | [`e74795c6d4d113f5e0d60aad318b73f3562997e7`](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/commit/e74795c6d4d113f5e0d60aad318b73f3562997e7) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/actions/runs/40249092298) |
| [netscaler-cve-2026-19490-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check) | [`31f088d1d14ee5527b1401931f64025178b5f4c2`](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/commit/31f088d1d14ee5527b1401931f64025178b5f4c2) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/actions/runs/40249635376) |
| [netscaler-cve-2026-88773-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check) | [`08d1907c825cbdb8eb98538444e56b41264aef91`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/commit/08d1907c825cbdb8eb98538444e56b41264aef91) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/actions/runs/40249086762) |
| [netscaler-cve-2026-88774-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check) | [`36e3f129f33153d241830be42e3f0b40a8140c92`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/commit/36e3f129f33153d241830be42e3f0b40a8140c92) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/actions/runs/40249081563) |
| [netscaler-cve-2026-88775-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check) | [`77404ae39999875528c478b6cb69c6f5b2dfb355`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/commit/77404ae39999875528c478b6cb69c6f5b2dfb355) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/actions/runs/40249076566) |
| [netscaler-cve-2026-88776-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check) | [`bd2c814e372178c6b36ea913427e0c270a0ae33b`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/commit/bd2c814e372178c6b36ea913427e0c270a0ae33b) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/actions/runs/40249070881) |
| [netscaler-cve-2026-88777-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check) | [`7ed1bec538682daf14468fead12e6e4f43b93780`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/commit/7ed1bec538682daf14468fead12e6e4f43b93780) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/actions/runs/40249065579) |
| [netscaler-cve-2026-88778-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check) | [`a4a5123c137c09b48c599a98857a47a1bcf2bcb1`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/commit/a4a5123c137c09b48c599a98857a47a1bcf2bcb1) | [6 passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/actions/runs/40249059659) |
| [node2shell-check](https://github.com/CompleTetech-Security/node2shell-check) | [`5bfd4caee620543889e11c4b6c3af7a0e57a1965`](https://github.com/CompleTetech-Security/node2shell-check/commit/5bfd4caee620543889e11c4b6c3af7a0e57a1965) | [12 passed](https://github.com/CompleTetech-Security/node2shell-check/actions/runs/40250130777) |
| [oci-runtime-inventory](https://github.com/CompleTetech-Security/oci-runtime-inventory) | [`f04bc7a5729e26dc9c067b0d610e35cd51633435`](https://github.com/CompleTetech-Security/oci-runtime-inventory/commit/f04bc7a5729e26dc9c067b0d610e35cd51633435) | [6 passed](https://github.com/CompleTetech-Security/oci-runtime-inventory/actions/runs/40250072619) |
| [scan-results-bridge](https://github.com/CompleTetech-Security/scan-results-bridge) | [`a9bd1b7af01d2cbde8c8923da9bd96021a3adab7`](https://github.com/CompleTetech-Security/scan-results-bridge/commit/a9bd1b7af01d2cbde8c8923da9bd96021a3adab7) | [6 passed](https://github.com/CompleTetech-Security/scan-results-bridge/actions/runs/40249851847) |
| [sharp-rsvg-rce-check](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check) | [`b4283ed0deb12e7b0568ff3c4b232f96935dfe4a`](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check/commit/b4283ed0deb12e7b0568ff3c4b232f96935dfe4a) | [6 passed](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check/actions/runs/40249169474) |
| [simplegit-rce-check](https://github.com/CompleTetech-Security/simplegit-rce-check) | [`38d2ae97b73d00992c979ba92800434e3f4cb3bd`](https://github.com/CompleTetech-Security/simplegit-rce-check/commit/38d2ae97b73d00992c979ba92800434e3f4cb3bd) | [6 passed](https://github.com/CompleTetech-Security/simplegit-rce-check/actions/runs/40244875480) |
| [sonicwall-sma1000-cve-2026-102255-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check) | [`fb2c56c690f03b0cd35208a7a916944f1635f592`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/commit/fb2c56c690f03b0cd35208a7a916944f1635f592) | [6 passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/actions/runs/40249098500) |
| [sonicwall-sma1000-cve-2026-102256-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check) | [`79b125a99fd8308c47703823543c2c462a4b5206`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/commit/79b125a99fd8308c47703823543c2c462a4b5206) | [6 passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/actions/runs/40249054122) |
| [sonicwall-sma1000-cve-2026-102257-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check) | [`8e4d0af8dba5a7ff0bfa97c78ffe67cd8fa0bf31`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/commit/8e4d0af8dba5a7ff0bfa97c78ffe67cd8fa0bf31) | [6 passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/actions/runs/40249048581) |
| [sonicwall-sma1000-cve-2026-102258-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check) | [`f511b0a2f507777084a1f3322ff07e16ee02a7cb`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/commit/f511b0a2f507777084a1f3322ff07e16ee02a7cb) | [6 passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/actions/runs/40249043155) |
| [vm2-nesting-check](https://github.com/CompleTetech-Security/vm2-nesting-check) | [`57c2448c32d82894d3ddd1af1b184436d97ddf3e`](https://github.com/CompleTetech-Security/vm2-nesting-check/commit/57c2448c32d82894d3ddd1af1b184436d97ddf3e) | [6 passed](https://github.com/CompleTetech-Security/vm2-nesting-check/actions/runs/40244871958) |

## Initial audit: what was verified

All 48 repositories visible in the `completetech-security` organization were
inventoried through authenticated GitHub metadata. Each had a successful hosted
workflow on its exact default-branch commit below, and none had an open PR.
The 12 open issues were all in this reference repository. A successful workflow
is evidence about that revision's configured checks; it does not prove every
roadmap requirement, independent review, exploitability or production readiness.

Fresh local Python 3.14 checks: Node2Shell ran 61 tests successfully; Atlassian
ran 53 with one skip; Flowise ran 65 with two skips. Those two family checkers
were checked out separately at the commits listed below. Other family test
suites were not rerun locally during this audit. Tests used synthetic inputs.

## Initial audit: original issue disposition

Completed implementation work is distinguished from the broader original scope.
The issue bodies retain their historical requirements and dated delivery notes.

| Issue | Verified delivery | Remaining scope / disposition |
| --- | --- | --- |
| [#2](https://github.com/completetech-security/node2shell-check/issues/2) | First three implementations and later exploit repositories merged; receipts below | Keep the parent open for incomplete children. The October 23 description of the first PRs as unmerged is historical. |
| [#3](https://github.com/completetech-security/node2shell-check/issues/3) | Separate NetScaler, Ivanti, BeyondTrust, SonicWall and FortiMail checkers exist | Keep open for reconciliation of portfolio CSV/configuration and external-threat metadata requirements against every destination. A per-CVE version checker does not establish all original grouped acceptance criteria. |
| [#4](https://github.com/completetech-security/node2shell-check/issues/4) | 20 separate additional Node advisory repositories, plus Node2Shell | Keep open for the complete advisory coverage matrix and lockfile/container evidence and feature-metadata collection requirements. Existing implementations accept operator observations; do not call these runtime attestation. |
| [#6](https://github.com/completetech-security/node2shell-check/issues/6) | Sharp/library selection, provenance, independent conditions, mitigation and reports implemented | Keep open: lockfile/SBOM ingestion, bounded ELF inspection and SVG/source mitigation candidates from the original scope are absent. PIE/libc are operator observations. |
| [#7](https://github.com/completetech-security/node2shell-check/issues/7) | Atlassian checker covers all eight products with per-branch fixes, JSON/CSV inventories, uncertainty and reports | Core checker acceptance verified. Broader local product-file adapters are not claimed; the destination checklist still records omission of a dedicated evidence-confidence field. |
| [#8](https://github.com/completetech-security/node2shell-check/issues/8) | Flowise and flowise-components assessed independently; npm lockfiles/declarations, explicit inventory, uncertainty and reports | Core checker acceptance verified. Direct container-image parsing and owner aggregation are not claimed; optional OCI work remains #12. |
| [#9](https://github.com/completetech-security/node2shell-check/issues/9) | Separate Engine/CLI, Desktop and go-archive comparisons; disputed archive range remains unknown | Keep open: CI YAML/shell source scanning, command direction, alias/wrapper and variable-argument fixtures are absent. |
| [#10](https://github.com/completetech-security/node2shell-check/issues/10) | simple-git affected interval, gap uncertainty, fixed line and operator preconditions implemented | Keep open: installed-dependency ingestion and import-bound clone/mirror source candidates, relative locations and ambiguity fixtures are absent. |
| [#11](https://github.com/completetech-security/node2shell-check/issues/11) | vm2 exact interval and fixed line, independent operator observations implemented | Keep open: JS/TS NodeVM construction/configuration analysis, spreads/defaults and trust-boundary candidate fixtures are absent. |
| [#12](https://github.com/completetech-security/node2shell-check/issues/12) | No `oci-runtime-inventory` repository in the audited organization | Not implemented; retain as optional supporting work. Requires bounded archive/layer/whiteout semantics, hostile fixtures and consumer adapters. |
| [#13](https://github.com/completetech-security/node2shell-check/issues/13) | Contracts, embedded snapshots and helpers bundled into implemented scanners | Keep open: signed distribution, publisher trust, key rotation, expiry and rollback remain deferred and unimplemented. Checksums are not signatures; do not introduce a mandatory shared runtime. |
| [#14](https://github.com/completetech-security/node2shell-check/issues/14) | No `scan-results-bridge` repository in the audited organization | Not implemented; retain as optional supporting work. Normalize actual per-checker result contracts before SARIF/NDJSON conversion; the old separate shared-rules-repository dependency is superseded by bundled contracts. |

The core acceptance for #7 and #8 is narrower than every adapter mentioned in
those proposals' scope sections. The remaining adapters are tracked in
[Atlassian #7](https://github.com/completetech-security/atlassian-cve-2026-21589-check/issues/7)
and [Flowise #7](https://github.com/completetech-security/flowise-cve-2026-69254-check/issues/7).
No unchecked requirement is silently marked implemented here. Every other
incomplete original ticket remains open.

## Exact hosted receipts

Links pin the audited commit and a successful workflow for that same SHA. They
are repository build/test evidence only. No live targets were scanned.

| Repository | Audited default-branch commit | Successful workflow |
| --- | --- | --- |
| [atlassian-cve-2026-21589-check](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check) | [`ae2eb4bf0e43ece8ddc736363231fdd380709a7e`](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check/commit/ae2eb4bf0e43ece8ddc736363231fdd380709a7e) | [passed](https://github.com/CompleTetech-Security/atlassian-cve-2026-21589-check/actions/runs/40111747853) |
| [beyondtrust-remote-support-cve-2026-102764-check](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check) | [`646a743fd1ae9240c3674fde0cb9f3bc765933b8`](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/commit/646a743fd1ae9240c3674fde0cb9f3bc765933b8) | [passed](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/actions/runs/40111756318) |
| [copyescape-check](https://github.com/CompleTetech-Security/copyescape-check) | [`a808351e418f1471b5c49e4594ddd9b3e8e75a63`](https://github.com/CompleTetech-Security/copyescape-check/commit/a808351e418f1471b5c49e4594ddd9b3e8e75a63) | [passed](https://github.com/CompleTetech-Security/copyescape-check/actions/runs/40111764893) |
| [docker-hub-pat-check](https://github.com/CompleTetech-Security/docker-hub-pat-check) | [`d60fbda312c6b25da1eea1539ea7345e56551ea0`](https://github.com/CompleTetech-Security/docker-hub-pat-check/commit/d60fbda312c6b25da1eea1539ea7345e56551ea0) | [passed](https://github.com/CompleTetech-Security/docker-hub-pat-check/actions/runs/40111773281) |
| [flowise-cve-2026-69254-check](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check) | [`59745fbca4e3136832bbafcbf9a35dfbeb5bbbeb`](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check/commit/59745fbca4e3136832bbafcbf9a35dfbeb5bbbeb) | [passed](https://github.com/CompleTetech-Security/flowise-cve-2026-69254-check/actions/runs/40111782286) |
| [fortimail-cve-2026-104286-check](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check) | [`a7d71b820fcd3a2622e9dd2ef476a34b51e3f636`](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/commit/a7d71b820fcd3a2622e9dd2ef476a34b51e3f636) | [passed](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/actions/runs/40111381059) |
| [ivanti-connect-secure-cve-2026-104935-check](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check) | [`44295b92f635d6269a9200c91096807ceaaede66`](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/commit/44295b92f635d6269a9200c91096807ceaaede66) | [passed](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/actions/runs/40111391569) |
| [netscaler-cve-2026-19489-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check) | [`f3b3d895e2d6b74b3241f8a702cdb9dfe5cd518c`](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/commit/f3b3d895e2d6b74b3241f8a702cdb9dfe5cd518c) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/actions/runs/40111429603) |
| [netscaler-cve-2026-19490-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check) | [`9bd816d07336a0978fcc581f75da1a15c574630d`](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/commit/9bd816d07336a0978fcc581f75da1a15c574630d) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/actions/runs/40111401724) |
| [netscaler-cve-2026-88771-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check) | [`bdffcb7bd640191f7673560c87242de55f62b330`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check/commit/bdffcb7bd640191f7673560c87242de55f62b330) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check/actions/runs/40111950063) |
| [netscaler-cve-2026-88772-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check) | [`a76d189bf4066f0720e84899f07b216688b0c2aa`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check/commit/a76d189bf4066f0720e84899f07b216688b0c2aa) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check/actions/runs/40111956866) |
| [netscaler-cve-2026-88773-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check) | [`b7b4e17728ddbea849491ca27c0450d2a496210f`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/commit/b7b4e17728ddbea849491ca27c0450d2a496210f) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/actions/runs/40111437417) |
| [netscaler-cve-2026-88774-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check) | [`465af6442a0bef133a8e7217a7390b94c99bdb07`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/commit/465af6442a0bef133a8e7217a7390b94c99bdb07) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/actions/runs/40111445978) |
| [netscaler-cve-2026-88775-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check) | [`b1d8377cda4a8c45bf678184edc744983771ff20`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/commit/b1d8377cda4a8c45bf678184edc744983771ff20) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/actions/runs/40111455323) |
| [netscaler-cve-2026-88776-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check) | [`27b55ba54b48c94a6a572cae5099465433440d32`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/commit/27b55ba54b48c94a6a572cae5099465433440d32) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/actions/runs/40111466347) |
| [netscaler-cve-2026-88777-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check) | [`90114bb1770e570786e53673cf0788ff524b4fef`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/commit/90114bb1770e570786e53673cf0788ff524b4fef) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/actions/runs/40111475885) |
| [netscaler-cve-2026-88778-check](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check) | [`c27d173d82b9154f91b0542c7f2b441d9b55ed70`](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/commit/c27d173d82b9154f91b0542c7f2b441d9b55ed70) | [passed](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/actions/runs/40111485945) |
| [next-cache-rce-check](https://github.com/CompleTetech-Security/next-cache-rce-check) | [`05abb85c748f8662b6eee06ad91ec43fdcc94406`](https://github.com/CompleTetech-Security/next-cache-rce-check/commit/05abb85c748f8662b6eee06ad91ec43fdcc94406) | [passed](https://github.com/CompleTetech-Security/next-cache-rce-check/actions/runs/40104643294) |
| [node-cve-2026-105481-check](https://github.com/CompleTetech-Security/node-cve-2026-105481-check) | [`147a1f93b8b8f4aa80a0aecff86b21f26045c8bf`](https://github.com/CompleTetech-Security/node-cve-2026-105481-check/commit/147a1f93b8b8f4aa80a0aecff86b21f26045c8bf) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-105481-check/actions/runs/40111410889) |
| [node-cve-2026-105482-check](https://github.com/CompleTetech-Security/node-cve-2026-105482-check) | [`577e44aebd6762b069fbb8702b0d3d59e1babd21`](https://github.com/CompleTetech-Security/node-cve-2026-105482-check/commit/577e44aebd6762b069fbb8702b0d3d59e1babd21) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-105482-check/actions/runs/40111736155) |
| [node-cve-2026-105483-check](https://github.com/CompleTetech-Security/node-cve-2026-105483-check) | [`2cd3b013ef1d8d2b85899f88629b4cd96d541329`](https://github.com/CompleTetech-Security/node-cve-2026-105483-check/commit/2cd3b013ef1d8d2b85899f88629b4cd96d541329) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-105483-check/actions/runs/40111744367) |
| [node-cve-2026-106069-check](https://github.com/CompleTetech-Security/node-cve-2026-106069-check) | [`6029af7832263b45f272c7652c494dad1d1b7db0`](https://github.com/CompleTetech-Security/node-cve-2026-106069-check/commit/6029af7832263b45f272c7652c494dad1d1b7db0) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106069-check/actions/runs/40111752257) |
| [node-cve-2026-106070-check](https://github.com/CompleTetech-Security/node-cve-2026-106070-check) | [`9409cc973889bb23069677fa0fe6a378fed82e1d`](https://github.com/CompleTetech-Security/node-cve-2026-106070-check/commit/9409cc973889bb23069677fa0fe6a378fed82e1d) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106070-check/actions/runs/40111759696) |
| [node-cve-2026-106071-check](https://github.com/CompleTetech-Security/node-cve-2026-106071-check) | [`a1f688e86133a79f3342ebf97c6e66c0300a4799`](https://github.com/CompleTetech-Security/node-cve-2026-106071-check/commit/a1f688e86133a79f3342ebf97c6e66c0300a4799) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106071-check/actions/runs/40111768135) |
| [node-cve-2026-106072-check](https://github.com/CompleTetech-Security/node-cve-2026-106072-check) | [`6e5e730c76979410c72d5fe348a26a450c196713`](https://github.com/CompleTetech-Security/node-cve-2026-106072-check/commit/6e5e730c76979410c72d5fe348a26a450c196713) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106072-check/actions/runs/40111775857) |
| [node-cve-2026-106073-check](https://github.com/CompleTetech-Security/node-cve-2026-106073-check) | [`b170281e609fb493c8d98fbef1fd22bf7ea7251a`](https://github.com/CompleTetech-Security/node-cve-2026-106073-check/commit/b170281e609fb493c8d98fbef1fd22bf7ea7251a) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106073-check/actions/runs/40111783613) |
| [node-cve-2026-106074-check](https://github.com/CompleTetech-Security/node-cve-2026-106074-check) | [`9d2143b506b5dfb25e60b0a8a97778cf7b74250f`](https://github.com/CompleTetech-Security/node-cve-2026-106074-check/commit/9d2143b506b5dfb25e60b0a8a97778cf7b74250f) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-106074-check/actions/runs/40111791684) |
| [node-cve-2026-56846-check](https://github.com/CompleTetech-Security/node-cve-2026-56846-check) | [`083a671a3b0a40c7679b1335df76da9de88ffa18`](https://github.com/CompleTetech-Security/node-cve-2026-56846-check/commit/083a671a3b0a40c7679b1335df76da9de88ffa18) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-56846-check/actions/runs/40111799465) |
| [node-cve-2026-56847-check](https://github.com/CompleTetech-Security/node-cve-2026-56847-check) | [`344dd9942fb447644fe3a2d71b4d0e653677c619`](https://github.com/CompleTetech-Security/node-cve-2026-56847-check/commit/344dd9942fb447644fe3a2d71b4d0e653677c619) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-56847-check/actions/runs/40111807434) |
| [node-cve-2026-56848-check](https://github.com/CompleTetech-Security/node-cve-2026-56848-check) | [`c95b7926d34bf8f947de016c4cd455e5077c50bf`](https://github.com/CompleTetech-Security/node-cve-2026-56848-check/commit/c95b7926d34bf8f947de016c4cd455e5077c50bf) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-56848-check/actions/runs/40111815203) |
| [node-cve-2026-56850-check](https://github.com/CompleTetech-Security/node-cve-2026-56850-check) | [`f7e8b0302cc1cfbe477e7999c337082153fe86a1`](https://github.com/CompleTetech-Security/node-cve-2026-56850-check/commit/f7e8b0302cc1cfbe477e7999c337082153fe86a1) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-56850-check/actions/runs/40111823476) |
| [node-cve-2026-58039-check](https://github.com/CompleTetech-Security/node-cve-2026-58039-check) | [`dae01448d5aec8a902012a1b86be710cc26d0f5e`](https://github.com/CompleTetech-Security/node-cve-2026-58039-check/commit/dae01448d5aec8a902012a1b86be710cc26d0f5e) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58039-check/actions/runs/40111830570) |
| [node-cve-2026-58040-check](https://github.com/CompleTetech-Security/node-cve-2026-58040-check) | [`96942108a44c6d7d92e35ee59c5dd41ef64af100`](https://github.com/CompleTetech-Security/node-cve-2026-58040-check/commit/96942108a44c6d7d92e35ee59c5dd41ef64af100) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58040-check/actions/runs/40111839697) |
| [node-cve-2026-58041-check](https://github.com/CompleTetech-Security/node-cve-2026-58041-check) | [`766b316346f039e1ac170942b45c03a32e04216b`](https://github.com/CompleTetech-Security/node-cve-2026-58041-check/commit/766b316346f039e1ac170942b45c03a32e04216b) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58041-check/actions/runs/40111849377) |
| [node-cve-2026-58042-check](https://github.com/CompleTetech-Security/node-cve-2026-58042-check) | [`2f05b42a9b64c126daacb643a6436712faff086a`](https://github.com/CompleTetech-Security/node-cve-2026-58042-check/commit/2f05b42a9b64c126daacb643a6436712faff086a) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58042-check/actions/runs/40111857710) |
| [node-cve-2026-58043-check](https://github.com/CompleTetech-Security/node-cve-2026-58043-check) | [`272290ea962786dbe6827be3f56ddcc9e27acd0e`](https://github.com/CompleTetech-Security/node-cve-2026-58043-check/commit/272290ea962786dbe6827be3f56ddcc9e27acd0e) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58043-check/actions/runs/40111866155) |
| [node-cve-2026-58044-check](https://github.com/CompleTetech-Security/node-cve-2026-58044-check) | [`d521869fae5911599a7217c21ad50cc118420a5a`](https://github.com/CompleTetech-Security/node-cve-2026-58044-check/commit/d521869fae5911599a7217c21ad50cc118420a5a) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58044-check/actions/runs/40111874797) |
| [node-cve-2026-58045-check](https://github.com/CompleTetech-Security/node-cve-2026-58045-check) | [`868a65209fa439176cc790c7b9f18c370bda9ce4`](https://github.com/CompleTetech-Security/node-cve-2026-58045-check/commit/868a65209fa439176cc790c7b9f18c370bda9ce4) | [passed](https://github.com/CompleTetech-Security/node-cve-2026-58045-check/actions/runs/40111884462) |
| [node2shell-check](https://github.com/CompleTetech-Security/node2shell-check) | [`621202aac88645308a0e0f7d1cd4004be9e6d5e4`](https://github.com/CompleTetech-Security/node2shell-check/commit/621202aac88645308a0e0f7d1cd4004be9e6d5e4) | [passed](https://github.com/CompleTetech-Security/node2shell-check/actions/runs/40109478199) |
| [php2shell-check](https://github.com/CompleTetech-Security/php2shell-check) | [`f244a5597cf6f2bf24d1501cc4730ff178bae97e`](https://github.com/CompleTetech-Security/php2shell-check/commit/f244a5597cf6f2bf24d1501cc4730ff178bae97e) | [passed](https://github.com/CompleTetech-Security/php2shell-check/actions/runs/40023849852) |
| [sharp-rsvg-rce-check](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check) | [`14955717ab29676828dc215e993d987c40e3f575`](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check/commit/14955717ab29676828dc215e993d987c40e3f575) | [passed](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check/actions/runs/40111943063) |
| [simplegit-rce-check](https://github.com/CompleTetech-Security/simplegit-rce-check) | [`30bbeced044d7e9e83a9371b4203616f5c7dd94e`](https://github.com/CompleTetech-Security/simplegit-rce-check/commit/30bbeced044d7e9e83a9371b4203616f5c7dd94e) | [passed](https://github.com/CompleTetech-Security/simplegit-rce-check/actions/runs/40111893526) |
| [sonicwall-sma1000-cve-2026-102255-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check) | [`0dfb36db16c9d7a7352221a0308135aa25e46df5`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/commit/0dfb36db16c9d7a7352221a0308135aa25e46df5) | [passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/actions/runs/40111420226) |
| [sonicwall-sma1000-cve-2026-102256-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check) | [`d9c505ed986e2a12c8f53b6b5ba3b28650071e53`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/commit/d9c505ed986e2a12c8f53b6b5ba3b28650071e53) | [passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/actions/runs/40111919059) |
| [sonicwall-sma1000-cve-2026-102257-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check) | [`9a437142787abf3ca1bcccab177655465b05d6d3`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/commit/9a437142787abf3ca1bcccab177655465b05d6d3) | [passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/actions/runs/40111927037) |
| [sonicwall-sma1000-cve-2026-102258-check](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check) | [`1ff33d9055bd157cbfc9178b43d65b2965bb6d6e`](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/commit/1ff33d9055bd157cbfc9178b43d65b2965bb6d6e) | [passed](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/actions/runs/40111935415) |
| [tinypool-options-rce-check](https://github.com/CompleTetech-Security/tinypool-options-rce-check) | [`9b603d37d15f259189a3df030a7d210366aec9b8`](https://github.com/CompleTetech-Security/tinypool-options-rce-check/commit/9b603d37d15f259189a3df030a7d210366aec9b8) | [passed](https://github.com/CompleTetech-Security/tinypool-options-rce-check/actions/runs/40111902229) |
| [vm2-nesting-check](https://github.com/CompleTetech-Security/vm2-nesting-check) | [`575ea16f8763f27a6e58dd708f46fe26112ea701`](https://github.com/CompleTetech-Security/vm2-nesting-check/commit/575ea16f8763f27a6e58dd708f46fe26112ea701) | [passed](https://github.com/CompleTetech-Security/vm2-nesting-check/actions/runs/40111911270) |

## Future delivery procedure

Implement future parsers in its exploit-specific destination, preserving
its existing result semantics, input bounds, standalone distribution and
publication protections. Original issues remain the acceptance authority.
Update the parent only after destination changes, meaningful synthetic tests,
review and hosted checks for the published revision are verified. Optional OCI,
conversion and signed-update work must not become prerequisites for running an
individual offline checker.
