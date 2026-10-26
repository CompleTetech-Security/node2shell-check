<p align="center">
  <img src="docs/images/banner.png" alt="node2shell-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <a href="https://github.com/completetech-security/node2shell-check/actions/workflows/tests.yml"><img src="https://github.com/completetech-security/node2shell-check/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1E3A8A" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-067647" alt="No dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

<h1 align="center">node2shell-check</h1>

<p align="center">
  <b>Version-based triage for Node2Shell (CVE-2026-111497) in Node.js runtimes and websites</b><br>
  Offline runtime assessment · passive website metadata · single-file, dependency-free Python
</p>

---

`node2shell-check` compares the Node.js version a runtime or website reports with the official upstream fix for each supported branch. You can assess a version you already know, collect metadata inside a deployed service, or inspect a website's ordinary public response.

It sends **no exploit payloads**, never decodes Brotli, and reports uncertainty honestly: a hidden, vendor-built, or conflicting version is `unknown`, never "safe".

> [!IMPORTANT]
> **Potential exposure is not confirmed exploitability.** Every result keeps exploitability `not_tested`. The vulnerability involves decoding attacker-controlled Brotli data, and a version alone cannot show whether an application reaches that code path. `fixed_version_reported` is not verification of a deployed patch. Treat every result as a prompt for an administrator to check.

Check only targets you are authorized to assess, and keep real target lists, inventories, and reports out of version control.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Input modes](#input-modes)
- [Understanding results](#understanding-results)
- [Reports and output](#reports-and-output)
- [Exit codes](#exit-codes)
- [Scope and limitations](#scope-and-limitations)
- [Optional tooling](#optional-tooling)
- [Documentation](#documentation)
- [Development and contributing](#development-and-contributing)
- [License](#license)

## Requirements

- Python 3.10 or later on Windows, macOS, or Linux. There is nothing to install; use `python3` where `python` is not Python 3.
- Node.js only if you run the optional collector, `collect-runtime.cjs`.

## Quick start

```sh
git clone https://github.com/completetech-security/node2shell-check.git
cd node2shell-check

# Compare a known version. Offline, no network calls.
python node2shell_check.py --node-version 24.22.0

# Collect metadata where the service runs (same Node.js binary), then assess it offline.
node collect-runtime.cjs > runtime.json
python node2shell_check.py --inventory runtime.json --format html --output report.html

# Check authorized websites listed one per line (start from websites.example.txt).
cp websites.example.txt websites.txt   # then replace the entries with your own authorized targets
python node2shell_check.py --input websites.txt --format html --output websites-report.html
```

With no `--format`, results are written as CSV to stdout. Run `python node2shell_check.py --help` for the complete option list, or see the [full reference](docs/REFERENCE.md).

## Input modes

All three modes can be combined in one run. Each input becomes its own observation with its own evidence; a supplied runtime version is never assumed to belong to a supplied URL.

| Mode | Option | Network | What it does |
| --- | --- | --- | --- |
| Known version | `--node-version VERSION` (repeatable) | None | Compares a version you obtained elsewhere. |
| Runtime inventory | `--inventory FILE` (repeatable) | None | Reads collector-compatible JSON (schema `1`) produced by `collect-runtime.cjs`. |
| Website metadata | URLs or domains as arguments, or `--input FILE` | Yes | Reads public response metadata from each supplied target. |

**Runtime inventory.** `collect-runtime.cjs` records version and build metadata from the Node.js binary that runs it. It never loads application code, reads environment variables, decompresses data, or opens a connection. It cannot attest vendor patch provenance, and its `build_source` defaults to `unknown`. Run it in the actual container or runtime you intend to assess; a host installation does not describe every container, function, or worker.

**Website metadata.** For each target the checker reads `robots.txt` and, if policy allows, makes an ordinary `GET` request to the supplied page. It uses verified TLS, an honest User-Agent, bounded responses, and request pacing. Redirects stay on the same host or its `www` counterpart, and HTTPS downgrades stop. It fetches nothing else and sends no compressed bodies, credentials, or crafted requests. Express or Next.js hints never become Node.js version evidence, and Brotli response compression does not prove that an application decodes request bodies. See [Requests made in website mode](docs/REFERENCE.md#requests-made-in-website-mode) for the full rules.

## Understanding results

Each observation receives one of four assessment statuses.

| Status | Meaning |
| --- | --- |
| `potentially_affected` | A plain Node.js version below its branch's fix is reported. Verify the deployed build and prioritize remediation. |
| `unsupported_runtime` | The version is on an older, unsupported upstream line. Verify vendor support and move to a supported, patched runtime. |
| `fixed_version_reported` | The reported version meets the fix. This is not independent verification of installed patches. |
| `unknown` | The version is missing, malformed, conflicting, vendor-qualified, custom-built, pre-release, possibly backported, or outside this rule snapshot. |

Upstream fixes in the embedded rule snapshot:

| Node.js branch | 22.x | 24.x | 26.x |
| --- | --- | --- | --- |
| **Fixed in** | 22.23.4 | 24.22.1 | 26.12.1 |

Thresholds come from the [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) and the release notes for [22.23.4](https://nodejs.org/en/blog/release/v22.23.4), [24.22.1](https://nodejs.org/en/blog/release/v24.22.1), and [26.12.1](https://nodejs.org/en/blog/release/v26.12.1), released 2026-10-21. The embedded rule snapshot is dated **2026-10-23**. The checker does not download or refresh rules, so rerunning an old copy does not update them.

Keep these distinctions in mind when reading a report:

- **Unknown is not an error.** A successful request may legitimately reveal no runtime version. Conversely, a `fixed_version_reported` observation elsewhere in a report does not erase an unsuccessful website check. Inspect each result's fetch outcome and the run's completeness as well as its assessment.
- **Reported is not verified.** A version copied from a Dockerfile, deployment label, or public header may differ from the process serving traffic. Headers can be stale, spoofed, or proxy-generated.
- **Vendor builds stay uncertain.** Vendor-qualified, custom-built, and pre-release versions remain `unknown`. Brotli metadata from the collector is context, not a patch verdict.

The [assessment methodology](docs/NODE2SHELL.md) documents each classification rule and the checks an administrator should perform. Result and evidence fields are listed in the [reference](docs/REFERENCE.md#result-fields).

## Reports and output

### HTML report

`--format html` produces a single offline, script-free file with a logo, summary tiles, every result with its evidence and next step, the upstream fix table, and run-completeness information. It follows the reader's light or dark theme and prints cleanly.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Example Node2Shell exposure report with the CompleteTech LLC logo" width="900">
  </picture>
</p>

<p align="center"><sub>Synthetic example built from reserved <code>example.*</code> domains and invented runtimes. <a href="docs/example-report.html">View the HTML</a>.</sub></p>

Use `--logo path/to/logo.png` and `--brand "Your Company"` to brand the report for your own organization.

### CSV and JSON

CSV (the default) and JSON suit spreadsheets and pipelines. Progress and diagnostics go to stderr, leaving stdout available for data.

Report schema `1.1` records the checker's executable SHA-256 (`tool_sha256`, not a publisher signature) and explicit run completeness in JSON, CSV, and HTML. Existing observation columns and inventory schema `1` remain compatible. An empty CSV report contains one summary row rather than a fabricated target. The JSON report is an object with top-level `tool`, `tool_version`, `tool_sha256`, `report_schema_version`, `rules_as_of`, `generated_at`, `complete`, and `results` fields. `complete: true` means the input loop finished, not that every request succeeded or every version was identified. See [CSV](docs/REFERENCE.md#csv), [JSON](docs/REFERENCE.md#json), and [result fields](docs/REFERENCE.md#result-fields) for details.

### Writing reports safely

- Existing output files are refused unless you pass `--force`. Input and logo files can never be the output destination, even with `--force`.
- The output directory must already exist. Files are prepared in a temporary file and published atomically; the default mode needs a filesystem that supports hard links and fails rather than weakening overwrite protection.
- The report is written after the input loop finishes or a keyboard interruption is handled. An interruption keeps completed observations and marks the report incomplete (`complete: false`). An interruption after a complete report has been published preserves that report. Abrupt termination, a crash, or power loss before the write can prevent report creation; there are no incremental checkpoints or automatic resume.
- CSV neutralizes spreadsheet formulas with a leading apostrophe and rejects NUL characters; a rejected write is an output error (exit 2).
- Reports can contain target URLs, response metadata, and operator-supplied inventory. Handle them as assessment records. There is no telemetry or automatic upload.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | The run completed without an operational error. Findings do not change this unless `--fail-on-finding` is set. |
| `1` | `--fail-on-finding` was set and at least one result is `potentially_affected` or `unsupported_runtime`. |
| `2` | An argument, input, or output error, or an operational failure, prevented one or more requested checks. This takes precedence over `1`. |
| `130` | The run was interrupted. Completed observations are retained where output can be written. |

Operational outcomes (for example timeouts or blocked requests) are separate from assessment results. Review both.

## Scope and limitations

- **Version triage only.** The checker never triggers the Brotli decoder, sends compressed request bodies, tests a crash, or attempts code execution. It does not review whether an application decompresses untrusted Brotli input through `node:zlib`.
- **Node.js only.** Thresholds are not applied to Bun, browser runtimes, standalone Brotli libraries, or other packages with similar version numbers. It is not a general vulnerability scanner.
- **Conservative by design.** Missing, malformed, conflicting, vendor-qualified, custom-build, pre-release, and uncovered-future versions stay `unknown`. `unsupported_runtime` is an upgrade-and-review result, not a claim that the vulnerability was reproduced on that release.
- **Fixed version reported is not a patched deployment.** Backports and vendor patches are not detected, and a missing header or successful scan does not show that a service is patched.
- **Local CLI, not a service.** Private and loopback addresses are supported for authorized internal assessment. The program is not designed to accept untrusted URLs from the internet.
- **Website checks stay narrow.** There is no crawling or endpoint enumeration, no automatic retries or access-control bypasses, no HTTP fallback after a TLS error, and no option to disable TLS verification or skip robots policy. A permissive `robots.txt` does not by itself grant permission to assess a website.

## Optional tooling

None of these changes the standalone checker, its embedded offline rule snapshot, or the Node2Shell inventory schema.

- **Signed-rule verification:** [offline TUF bundle verification](tools/signed_rules/README.md) uses separate optional dependencies and an explicitly provisioned public trust root. It never applies a rule update automatically.
- **Authenticated rule publication:** the [keyless publication channel](docs/KEYLESS_RULES.md) uses pinned GitHub/Sigstore publisher identity, expiring artifacts, and durable rollback checks. Updates produce a separate review artifact.
- **Family metadata tools:** [Node capability and build-context collection](docs/NODE_METADATA.md) produces separate formats that do not infer application exposure from available APIs, lockfile declarations, or image tags.

## Documentation

- [Full reference](docs/REFERENCE.md): every CLI option, inventory field, output field, and request rule
- [Assessment methodology](docs/NODE2SHELL.md): how each version is classified, with sources
- [Node advisory matrix](docs/NODE_ADVISORY_MATRIX.md): named Node.js advisories and their checker coverage
- [Exploit-specific checker repositories](docs/CHECKER_FAMILY.md): roadmap for one independent repository per exploit
- [Checker delivery status](docs/CHECKER_STATUS.md): dated merge and CI receipts and remaining roadmap scope
- [Changelog](CHANGELOG.md)

## Development and contributing

Issues and pull requests are welcome; start with [CONTRIBUTING.md](CONTRIBUTING.md). Report a security flaw in this checker as described in [SECURITY.md](SECURITY.md).

```sh
python -m unittest -v              # local-only tests; no external websites are contacted
python node2shell_check.py --help
```

Hosted CI runs the suite on Linux, Windows, and macOS with Python 3.10 and 3.14. For agents contributing to this repository, [AGENTS.md](AGENTS.md) contains the shared development instructions; [CLAUDE.md](CLAUDE.md) points Claude to them.

## License

Dual licensed: [AGPL-3.0](LICENSE), including commercial use that meets its terms, or a [commercial license](LICENSING.md#commercial-license) from CompleteTech LLC for closed-source products and services that don't fit the AGPL model. See [LICENSING.md](LICENSING.md) for details. The CompleteTech LLC name and logo are covered by neither license; see [BRAND_ASSETS.md](BRAND_ASSETS.md).

<p align="center">
  <a href="https://complete.tech"><img src="assets/logo.png" alt="CompleteTech LLC" width="160"></a><br>
  <sub>Built by <a href="https://complete.tech">CompleteTech LLC</a> · Innovation at Every Integration</sub>
</p>
