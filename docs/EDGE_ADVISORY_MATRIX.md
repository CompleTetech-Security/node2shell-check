# Edge advisory ingestion and external-threat coverage

Reviewed 2026-10-25 against the actual standalone entry points, input schemas and
embedded rules. All 17 named edge advisories have CSV ingestion and independent
per-device rule evidence; flag names vary below. No combined edge scanner is
introduced. The first two NetScaler checkers already carry separately dated
CISA-ADP KEV and vendor exploitation metadata. The remaining explicit KEV-field
updates are separate PRs and remain pending until their review/CI gates pass.

CISA's official [kev-data mirror](https://github.com/cisagov/kev-data) confirms
catalog **2026.10.23**, released **2026-10-23T19:30:18.9209Z**. Exact source:
[revision b9c486ef8f3ba0709bb662ae843ffee96953c400](https://github.com/cisagov/kev-data/blob/b9c486ef8f3ba0709bb662ae843ffee96953c400/known_exploited_vulnerabilities.json).
Full catalog SHA-256:
`97a6e54bc74c651ab3c55657191db9adec6c63b05ca54e4205327cfd97a8fb70`.
The direct CISA feed was unavailable during this review; the official mirror
provides the dated source. No checker fetches it while assessing inventories.
External listing is not local exploitation, and not_listed is not a safety claim.

| Advisory / independent checker | CSV input | Configuration/deployment scope | KEV snapshot / delivery |
| --- | --- | --- | --- |
| [CVE-2026-88772](https://github.com/CompleTetech-Security/netscaler-cve-2026-88772-check/blob/a76d189bf4066f0720e84899f07b216688b0c2aa/README.md) | `--inventory FILE.csv` | Complete DTLS export, ordered add/set/defaults, per-vserver identity; incomplete/unsupported remains unknown | listed 2026-09-27; existing ADP metadata in report |
| [CVE-2026-88771](https://github.com/CompleTetech-Security/netscaler-cve-2026-88771-check/blob/bdffcb7bd640191f7673560c87242de55f62b330/README.md) | `--inventory FILE.csv` | No optional feature prerequisite; never gate on DTLS | listed 2026-09-27; existing ADP metadata in report |
| [CVE-2026-102258](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/blob/1ff33d9055bd157cbfc9178b43d65b2965bb6d6e/README.md) | `--csv-list FILE` | Exact branch/model, authenticated/interface condition and custom-build uncertainty; table gaps unknown | [not_listed; PR #10](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102258-check/pull/10) (under review) |
| [CVE-2026-102257](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/blob/9a437142787abf3ca1bcccab177655465b05d6d3/README.md) | `--csv-list FILE` | Exact branch/model, authenticated/interface condition and custom-build uncertainty; table gaps unknown | [not_listed; PR #11](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102257-check/pull/11) (under review) |
| [CVE-2026-102256](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/blob/d9c505ed986e2a12c8f53b6b5ba3b28650071e53/README.md) | `--csv-list FILE` | Exact branch/model, authenticated/interface condition and custom-build uncertainty; table gaps unknown | [not_listed; PR #11](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102256-check/pull/11) (under review) |
| [CVE-2026-102764](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/blob/646a743fd1ae9240c3674fde0cb9f3bc765933b8/README.md) | `--csv-list FILE` | Separate self-hosted patch evidence and provider-managed SaaS uncertainty | [listed 2026-10-16; PR #8](https://github.com/CompleTetech-Security/beyondtrust-remote-support-cve-2026-102764-check/pull/8) (under review) |
| [CVE-2026-88778](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/blob/c27d173d82b9154f91b0542c7f2b441d9b55ed70/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88778-check/pull/10) (under review) |
| [CVE-2026-88777](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/blob/90114bb1770e570786e53673cf0788ff524b4fef/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88777-check/pull/10) (under review) |
| [CVE-2026-88776](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/blob/27b55ba54b48c94a6a572cae5099465433440d32/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88776-check/pull/10) (under review) |
| [CVE-2026-88775](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/blob/b1d8377cda4a8c45bf678184edc744983771ff20/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88775-check/pull/10) (under review) |
| [CVE-2026-88774](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/blob/465af6442a0bef133a8e7217a7390b94c99bdb07/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88774-check/pull/10) (under review) |
| [CVE-2026-88773](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/blob/b7b4e17728ddbea849491ca27c0450d2a496210f/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-88773-check/pull/10) (under review) |
| [CVE-2026-19489](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/blob/f3b3d895e2d6b74b3241f8a702cdb9dfe5cd518c/README.md) | `--csv-list FILE` | Advisory-specific typed operator observations; independent variant/build provenance | [not_listed; PR #10](https://github.com/CompleTetech-Security/netscaler-cve-2026-19489-check/pull/10) (under review) |
| [CVE-2026-102255](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/blob/0dfb36db16c9d7a7352221a0308135aa25e46df5/README.md) | `--csv-list FILE` | Exact branch/model, authenticated/interface condition and custom-build uncertainty; table gaps unknown | [not_listed; PR #14](https://github.com/CompleTetech-Security/sonicwall-sma1000-cve-2026-102255-check/pull/14) (under review) |
| [CVE-2026-19490](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/blob/9bd816d07336a0978fcc581f75da1a15c574630d/README.md) | `--csv-list FILE` | Gateway/AAA and branch-specific SAML observations; config patterns do not establish absence/reachability | [listed 2026-09-09; PR #13](https://github.com/CompleTetech-Security/netscaler-cve-2026-19490-check/pull/13) (under review) |
| [CVE-2026-104935](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/blob/44295b92f635d6269a9200c91096807ceaaede66/README.md) | `--csv FILE` | Version-only; backport source confidence and unknown uncovered releases retained | [listed 2026-10-13; PR #10](https://github.com/CompleTetech-Security/ivanti-connect-secure-cve-2026-104935-check/pull/10) (under review) |
| [CVE-2026-104286](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/blob/a7d71b820fcd3a2622e9dd2ef476a34b51e3f636/README.md) | `--list FILE` | IBE/exposure mitigation separate; cloud and disputed 7.0 remain unknown | [listed 2026-10-01; PR #12](https://github.com/CompleTetech-Security/fortimail-cve-2026-104286-check/pull/12) (under review) |

Use each tool's documented product/edition/variant fields and synthetic examples;
do not feed a generic CMDB schema blindly into every checker. Existing CSV
adapters validate columns and map explicit per-device facts. Absent versions,
conflicts, vendor/custom builds, incomplete configurations and uncovered future
releases remain unknown. Optional network mode is omitted because passive
responses cannot establish firmware patch/configuration state; no network mode
is needed to satisfy this offline delivery.

No raw configuration parser is invented for version-only advisories. Supported
configuration exports are conservative hints: the original DTLS parser's default,
explicit OFF, subsequent set, multiple-server and incomplete-export cases already
have fixtures. NetScaler 88771 is independent of DTLS. SaaS/vendor-managed evidence
is never assumed equivalent to a verified self-hosted patch. All outputs retain
local exploitability not_tested.

The linked pinned README revisions describe the audited baseline implementation;
new metadata PRs are separately identified and require exact-head hosted checks.
The original baseline CI receipts are in [CHECKER_STATUS.md](CHECKER_STATUS.md).
