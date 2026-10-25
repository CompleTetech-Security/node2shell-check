# Exploit-specific checker repositories

Delivery policy recorded **2026-10-23** for [roadmap issue #2](https://github.com/completetech-security/node2shell-check/issues/2).

For the dated delivery audit, exact default-branch commits and CI receipts, see
[checker delivery status](CHECKER_STATUS.md). The original first-delivery notes
below describe scope, not the current merge state.
The [named Node advisory matrix](NODE_ADVISORY_MATRIX.md) maps the July/October
CVE headings to the existing standalone repositories and pinned snapshots.

## One repository per exploit

Each distinct exploit or advisory receives its own standalone repository, Python
entry point, embedded rule snapshot, tests, and documentation. This is a
maintainer decision. A product name is not permission to combine
unrelated vulnerabilities into one scanner. The same exploit can affect several
packages, products, editions, or supported version branches; those belong in the
same checker when the advisory establishes the relationship.

The existing `node2shell-check` and `php2shell-check` are the implementation and
presentation references. Node2Shell continues to cover CVE-2026-111497 through
its existing CLI and schema. Its public behavior is unchanged by this roadmap.

## First implementation set

| Repository | Exploit scope | Evidence emphasis | Tracking |
| --- | --- | --- | --- |
| [next-cache-rce-check](https://github.com/completetech-security/next-cache-rce-check) | GHSA-673q-mjm6-r5xr | Installed Next.js versions; separate App Router, Cache Components and typed-array source candidates | [#5](https://github.com/completetech-security/node2shell-check/issues/5) |
| [netscaler-cve-2026-88771-check](https://github.com/completetech-security/netscaler-cve-2026-88771-check) | CVE-2026-88771 only | Product/edition and firmware branch; no extra feature prerequisite | [#3](https://github.com/completetech-security/node2shell-check/issues/3) |
| [netscaler-cve-2026-88772-check](https://github.com/completetech-security/netscaler-cve-2026-88772-check) | CVE-2026-88772 only | Firmware plus effective DTLS configuration for each virtual server | [#3](https://github.com/completetech-security/node2shell-check/issues/3) |

Repository existence is not a release assertion. The implementation pull
requests, their exact commit checks, and the acceptance criteria in the linked
issues determine delivery status. Do not close the parent roadmap after this
first set.

The Next.js rule derives from the [maintainer advisory](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr).
The NetScaler checkers use the relevant individual CVE entries in
[CTX697096](https://support.citrix.com/external/article/CTX697096/citrix-netscaler-adc-and-citrix-netscale.html).
The DTLS checker also needs the [virtual-server command reference](https://developer-docs.netscaler.com/en-us/adc-command-reference-int/current-release/vpn/vpn-vserver.html).
Each destination records its exact version boundaries, verified claims, source
dates, and limitations alongside its embedded rule. These links are provenance,
not network dependencies of a scan.

## How the original grouped issues change

| Original proposal | Required delivery interpretation |
| --- | --- |
| `edge-kev-check` / #3 | A coordination issue for separate NetScaler, BeyondTrust, Ivanti and other individually verified exploits. No combined edge scanner. |
| `node-security-posture` / #4 | Keep Node2Shell in its current repository. Give each additional verified Node.js exploit its own repository. |
| Next.js / #5 | One repository for GHSA-673q-mjm6-r5xr. Do not invent a CVE identifier. |
| Sharp / #6 | One repository for GHSA-wq5f-xc86-pv6w (librsvg CVE-2026-96889), with bundled and system librsvg evidence kept distinct. |
| Atlassian / #7 | One repository for CVE-2026-21589. The multiple affected products are branches of the same advisory, not separate exploits. |
| Flowise / #8 | One repository for GHSA-3769-jgqc-cxm7 / CVE-2026-69254. Its two package names are assessed independently within the same exploit. |
| Docker / #9 | One repository for CVE-2026-17106 ("CopyEscape" in the research report). Engine, client and Desktop use separate component/version comparisons. |
| simple-git / #10 | One repository for GHSA-g4wm-2vf7-vfgr / CVE-2026-102826. Source matches remain candidate evidence without proved data flow. |
| vm2 / #11 | One repository for GHSA-8hr7-r645-pc6w / CVE-2026-92935. Keep NodeVM configuration and untrusted-code evidence separate. |
| OCI inventory / #12 | Deferred supporting capability. It must not require executing an image or become a mandatory checker dependency. |
| Shared rules/template / #13 | Bundle the contract, provenance and reusable implementation in each exploit repository. No separate shared-rules service is needed for the initial tools. |
| Results bridge / #14 | Deferred optional conversion. An individual checker must still emit useful offline reports without it. |

The research report and grouped issues supply leads, not executable thresholds.
All later repositories require a fresh verification of primary advisory
material before rules are enabled. In particular, the Docker archive-library
range discrepancy and incomplete SonicWall/Fortinet source retrieval must be
resolved before expanding detection into those unresolved ranges. No missing
source is replaced by a guessed threshold or a “safe” result.

## Self-contained distribution

Every checker must run from its own checkout, and its distributed Python entry
point must run when copied elsewhere. Shared implementation can be copied or
bundled at build time, with its provenance retained. Scans must not need another
checker repository, an installed shared package, a live feed, or network access.

Each repository carries its own:

- Source-linked embedded rule snapshot and verification date.
- Versioned result/evidence contract and synthetic examples.
- Bounded parsers, conservative classification and meaningful boundary tests.
- JSON, CSV and script-free HTML reporting with consistent findings and coverage.
- README, methodology, CLI reference, security/contribution instructions and changelog.
- AGPL-3.0/commercial licensing and separately controlled CompleteTech trademarks.
- CI on Linux, Windows and macOS with Python 3.10 and a current supported Python.

Hashes identify bytes; they are not publisher signatures. Signed updates are a
separate future capability requiring a reviewed trust and rollback design. The
initial checkers do not offer an unauthenticated rule-update shortcut.

## Evidence and acceptance

Keep version, configuration, source candidates, mitigation, authorized
reachability and external threat reporting separate. Local `exploitability`
always remains `not_tested`. CISA KEV inclusion or a vendor exploitation report
does not establish that the assessed asset is reachable or exploitable.

An installed affected version can support `potentially_affected`; static source
patterns alone cannot upgrade it to confirmed exploitation. An effective
configuration observation is scoped to its export and asset. Incomplete exports,
dynamic source code, version conflicts, unknown editions, vendor/custom builds,
prereleases and uncovered branches must retain their uncertainty.

Validate both sides of every threshold, independent precondition/mitigation
states, malformed and bounded inputs, output escaping and privacy, deterministic
serialization, overwrite protection, standalone execution and exit policies.
Tests use synthetic inputs and, where a network component is justified, loopback
only. No test executes target application code or sends an exploit payload.

Local checks and hosted CI are separate evidence. Record the actual published
commit tested; a green check on an earlier revision does not validate a later
change. Report any remaining scope explicitly, and leave its tracking issue open.

The [edge advisory ingestion/threat matrix](EDGE_ADVISORY_MATRIX.md) records
actual CSV/configuration coverage and dated external KEV provenance.
