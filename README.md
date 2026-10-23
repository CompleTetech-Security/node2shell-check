<p align="center">
  <a href="https://complete.tech"><img src="assets/logo.png" alt="CompleteTech LLC" width="160"></a>
</p>

# node2shell-check

[![Tests](https://github.com/CompleteTech-LLC/node2shell-check/actions/workflows/tests.yml/badge.svg)](https://github.com/CompleteTech-LLC/node2shell-check/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-1E3A8A)
![No dependencies](https://img.shields.io/badge/dependencies-none-067647)
[![AGPL-3.0 or commercial license](https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B)](LICENSING.md)

**Node2Shell exposure triage for CVE-2026-111497.** Assess reported Node.js
versions, collect runtime metadata locally, or inspect ordinary public website
responses. Export CSV, JSON, or a branded offline HTML report.

Built on the approach used by [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check):
one Python file, no third-party dependencies, no exploit payloads, and explicit
uncertainty. Python 3.10+ runs the checker on Windows, macOS, and Linux.

## Quick start

```sh
git clone https://github.com/CompleteTech-LLC/node2shell-check.git
cd node2shell-check

# Assess a version you have obtained from the deployed runtime; no network calls.
python node2shell_check.py --node-version 24.22.0

# Collect metadata inside the actual service/container, then assess it offline.
node collect-runtime.cjs > runtime.json
python node2shell_check.py --inventory runtime.json --format html --output report.html

# Inspect an authorized website's public response metadata.
python node2shell_check.py https://example.com --format json

# Process a list of authorized websites.
python node2shell_check.py --input websites.txt --format html --output websites-report.html
```

The optional collector requires Node.js only when you run it. The Python checker
does not install packages, invoke Node.js, run your application, or decode Brotli.
Existing report files are preserved unless you pass `--force`.

## What the results mean

| Status | Meaning |
| --- | --- |
| `potentially_affected` | A plain Node.js version is below its supported branch's upstream fix. Verify the actual deployed build and prioritize remediation. |
| `fixed_version_reported` | A reported version meets the branch's fix threshold. This is not independent verification of installed patches. |
| `unsupported_runtime` | The reported version is on an older, unsupported upstream line. Verify vendor support and move to a supported, patched runtime. |
| `unknown` | Evidence is missing, conflicting, qualified, custom-built, prerelease, or outside this rule snapshot. |

| Node.js branch | Fixed release |
| --- | --- |
| 22.x | 22.23.4 |
| 24.x | 24.22.1 |
| 26.x | 26.12.1 |

The [Node.js security advisory](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
and release notes for [22.23.4](https://nodejs.org/en/blog/release/v22.23.4),
[24.22.1](https://nodejs.org/en/blog/release/v24.22.1), and
[26.12.1](https://nodejs.org/en/blog/release/v26.12.1) establish these fixes,
released October 21, 2026. The embedded rule snapshot is dated **2026-10-23**.

**Every result keeps exploitability as `not_tested`.** The vulnerability involves
decoding attacker-controlled Brotli data; a runtime version alone cannot show
whether an application reaches that code path. See the
[assessment methodology](docs/NODE2SHELL.md).

## Choose the evidence that answers your question

- **Runtime inventory:** run the collector in each deployed runtime or container.
  It records version/build metadata without hostnames, environment variables,
  tokens, or application data. It cannot establish vendor patch provenance.
- **Known version:** use repeatable `--node-version` arguments for an offline
  comparison. Record where your versions came from outside the report if needed.
- **Website metadata:** inspect an authorized URL with ordinary GET requests.
  Hidden Node.js versions remain `unknown`. Express or Next.js hints never become
  Node.js version evidence. Response compression does not prove request decoding.

You can combine these input modes in one report. Each observation retains its
own evidence; an offline version is never silently attached to a website.

## The report

`--format html` writes a self-contained, script-free report with summary counts,
assessment details, remediation guidance, and source links. It supports light
and dark themes and printing. The [example report](docs/example-report.html)
contains only synthetic observations.

```sh
python node2shell_check.py --node-version 22.23.3 --node-version 24.22.1 \
  --format html --output report.html --brand "Your Company" --logo your-logo.png
```

CSV supports spreadsheets; JSON preserves structured evidence and includes a
`complete` flag. Use `--fail-on-finding` in a pipeline when potentially affected
or unsupported runtimes should produce exit code 1. Operational failures use
exit code 2; interruption uses 130. See the [full reference](docs/REFERENCE.md).

## Website request boundaries

The checker reads `robots.txt`, then the supplied page if allowed. It uses
verified TLS, a descriptive User-Agent, bounded response sizes, and request
pacing. Redirects are restricted to the same host or its `www` counterpart;
HTTPS downgrades stop. It sends no compressed bodies, exploit probes, credentials,
or automatic retries, and it does not fetch linked assets or decompress responses.

Use it only for targets you are authorized to assess. Private/local addresses are
supported for authorized internal checks. This local CLI is not an arbitrary-URL
web scanning service. Proxy environment variables are ignored.

## Documentation and development

- [Assessment methodology and sources](docs/NODE2SHELL.md)
- [CLI, inventory, outputs, and request reference](docs/REFERENCE.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)
- [Repository instructions for agents](AGENTS.md)

```sh
python -m unittest -v
python node2shell_check.py --help
```

Tests use synthetic data, mocks, and loopback HTTP fixtures. They do not scan
external websites.

## License

Available under [GNU AGPL-3.0](LICENSE) or a commercial license from CompleteTech
LLC; see [LICENSING.md](LICENSING.md). Brand assets have separate terms in
[BRAND_ASSETS.md](BRAND_ASSETS.md).

Built by [CompleteTech LLC](https://complete.tech) · Innovation at Every Integration
