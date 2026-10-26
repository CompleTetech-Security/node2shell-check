# Named Node.js advisory coverage matrix

Reviewed **2026-10-25** against the named CVE headings in the official
[July release advisory](https://nodejs.org/en/blog/vulnerability/july-2026-security-releases)
and [October release advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
The 21 named entries map to Node2Shell plus 20 separate repositories. Dependency
updates mentioned without a separate CVE heading are not an assertion of coverage
for every vulnerability in those upstream dependencies. Earlier CVEs referenced
as incomplete fixes are not silently treated as separate new July/October entries.

The table records the **existing embedded snapshots**, not new thresholds or
independently verified deployments. Each pinned snapshot contains the exact
preconditions, lifecycle/branch exclusions, sources, caveats and its earlier
verification date. The 20 additional Node checkers' audited default-branch CI
receipts are in the historical initial-audit table in
[CHECKER_STATUS.md](CHECKER_STATUS.md#exact-hosted-receipts). Those audited CI
revisions are distinct from the older pinned snapshot revisions below; this
matrix does not claim a CI run on each snapshot commit. The newer Node2Shell
and OCI delivery receipts are in its current merge-commit table. No runtime,
website or production deployment was assessed for this matrix.

| CVE / checker | Reported fixes by covered major | Pinned evidence contract and preconditions |
| --- | --- | --- |
| [CVE-2026-111497 / Node2Shell](https://github.com/completetech-security/node2shell-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Methodology](NODE2SHELL.md) |
| [CVE-2026-105481](https://github.com/CompleTetech-Security/node-cve-2026-105481-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-105481-check/blob/147a1f93b8b8f4aa80a0aecff86b21f26045c8bf/advisory.json), verified 2026-10-24 |
| [CVE-2026-105482](https://github.com/CompleTetech-Security/node-cve-2026-105482-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-105482-check/blob/577e44aebd6762b069fbb8702b0d3d59e1babd21/advisory.json), verified 2026-10-24 |
| [CVE-2026-105483](https://github.com/CompleTetech-Security/node-cve-2026-105483-check) | 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-105483-check/blob/2cd3b013ef1d8d2b85899f88629b4cd96d541329/advisory.json), verified 2026-10-24 |
| [CVE-2026-106069](https://github.com/CompleTetech-Security/node-cve-2026-106069-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106069-check/blob/6029af7832263b45f272c7652c494dad1d1b7db0/advisory.json), verified 2026-10-24 |
| [CVE-2026-106070](https://github.com/CompleTetech-Security/node-cve-2026-106070-check) | 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106070-check/blob/9409cc973889bb23069677fa0fe6a378fed82e1d/advisory.json), verified 2026-10-24 |
| [CVE-2026-106071](https://github.com/CompleTetech-Security/node-cve-2026-106071-check) | 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106071-check/blob/a1f688e86133a79f3342ebf97c6e66c0300a4799/advisory.json), verified 2026-10-24 |
| [CVE-2026-106072](https://github.com/CompleTetech-Security/node-cve-2026-106072-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106072-check/blob/6e5e730c76979410c72d5fe348a26a450c196713/advisory.json), verified 2026-10-24 |
| [CVE-2026-106073](https://github.com/CompleTetech-Security/node-cve-2026-106073-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106073-check/blob/b170281e609fb493c8d98fbef1fd22bf7ea7251a/advisory.json), verified 2026-10-24 |
| [CVE-2026-106074](https://github.com/CompleTetech-Security/node-cve-2026-106074-check) | 22: 22.23.4; 24: 24.22.1; 26: 26.12.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-106074-check/blob/9d2143b506b5dfb25e60b0a8a97778cf7b74250f/advisory.json), verified 2026-10-24 |
| [CVE-2026-56846](https://github.com/CompleTetech-Security/node-cve-2026-56846-check) | 22: 22.23.2; 24: 24.18.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-56846-check/blob/083a671a3b0a40c7679b1335df76da9de88ffa18/advisory.json), verified 2026-10-24 |
| [CVE-2026-56847](https://github.com/CompleTetech-Security/node-cve-2026-56847-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-56847-check/blob/344dd9942fb447644fe3a2d71b4d0e653677c619/advisory.json), verified 2026-10-24 |
| [CVE-2026-56848](https://github.com/CompleTetech-Security/node-cve-2026-56848-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-56848-check/blob/c95b7926d34bf8f947de016c4cd455e5077c50bf/advisory.json), verified 2026-10-24 |
| [CVE-2026-56850](https://github.com/CompleTetech-Security/node-cve-2026-56850-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-56850-check/blob/f7e8b0302cc1cfbe477e7999c337082153fe86a1/advisory.json), verified 2026-10-24 |
| [CVE-2026-58039](https://github.com/CompleTetech-Security/node-cve-2026-58039-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58039-check/blob/dae01448d5aec8a902012a1b86be710cc26d0f5e/advisory.json), verified 2026-10-24 |
| [CVE-2026-58040](https://github.com/CompleTetech-Security/node-cve-2026-58040-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58040-check/blob/96942108a44c6d7d92e35ee59c5dd41ef64af100/advisory.json), verified 2026-10-24 |
| [CVE-2026-58041](https://github.com/CompleTetech-Security/node-cve-2026-58041-check) | 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58041-check/blob/766b316346f039e1ac170942b45c03a32e04216b/advisory.json), verified 2026-10-24 |
| [CVE-2026-58042](https://github.com/CompleTetech-Security/node-cve-2026-58042-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58042-check/blob/2f05b42a9b64c126daacb643a6436712faff086a/advisory.json), verified 2026-10-24 |
| [CVE-2026-58043](https://github.com/CompleTetech-Security/node-cve-2026-58043-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58043-check/blob/272290ea962786dbe6827be3f56ddcc9e27acd0e/advisory.json), verified 2026-10-24 |
| [CVE-2026-58044](https://github.com/CompleTetech-Security/node-cve-2026-58044-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58044-check/blob/d521869fae5911599a7217c21ad50cc118420a5a/advisory.json), verified 2026-10-24 |
| [CVE-2026-58045](https://github.com/CompleTetech-Security/node-cve-2026-58045-check) | 22: 22.23.2; 24: 24.18.1; 26: 26.5.1 | [Snapshot](https://github.com/CompleTetech-Security/node-cve-2026-58045-check/blob/868a65209fa439176cc790c7b9f18c370bda9ce4/advisory.json), verified 2026-10-24 |

## Evidence collection and its limits

A repository for every named CVE establishes implementation mapping, not the
whole original scope of [issue #4](https://github.com/completetech-security/node2shell-check/issues/4).
The Node tools accept explicit versions and bounded inventories with independent
operator observations; these do not attest runtime feature use, HTTP/2 server
configuration, Permission Model policy, resolver behavior, TLS identity handling,
startup-snapshot construction or SEA deployment. A static capability does not
prove an advisory precondition, nor does its absence clear an old version.

The runtime/build feature collector and npm declaration context are delivered
in [PR #22](https://github.com/CompleTetech-Security/node2shell-check/pull/22).
Collector output avoids app imports,
environment variables, hostnames, arguments, credentials and application data.
No matching source or inventory record can prove absence. Container metadata
support is delivered by optional [OCI PR #1](https://github.com/CompleTetech-Security/oci-runtime-inventory/pull/1).
Neither support tool is a mandatory runtime dependency of these standalone tools.

The embedded snapshots preserve important exclusions: not every listed CVE
covers every active major. In particular, do not add a missing major to a
snapshot by extrapolating a universal fix, reuse another advisory's fix table,
or classify custom/prerelease/future builds as verified safe. Local
exploitability remains `not_tested`, independently of external exploitation
reports and lifecycle upgrade guidance.

Both supporting PRs are merged with passing hosted checks on their actual
merge commits. [Delivery receipts](CHECKER_STATUS.md#actual-merge-commit-ci-receipts)
pin those commits and distinguish build/test evidence from runtime attestation.
