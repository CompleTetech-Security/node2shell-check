# Contributing

Open an issue for a bug or focused improvement, then submit a pull request.
For a security flaw in this checker, follow [SECURITY.md](SECURITY.md).

## Local development

Python 3.10+ is sufficient for the checker and Python tests. There are no
third-party Python runtime or test dependencies. The optional runtime collector
uses Node.js when explicitly invoked.

```sh
python -m unittest -v
python node2shell_check.py --help
git diff --check
```

Keep the Python checker usable as one file. Preserve verified TLS, robots
checks, descriptive User-Agent, pacing, bounded bodies and redirects, direct
connections without environment-proxy inheritance, and explicit uncertainty.
Do not add exploit payloads, compressed-body probes, authentication bypasses, or
automatic retries around restrictions.

Assessment changes must cite official Node.js advisories and include focused
branch-boundary and qualifier tests. Keep version provenance, vendor/custom
build uncertainty, unsupported runtimes, and future branches distinct.
`fixed_version_reported` does not mean independently verified patch state.
Exploitability must remain `not_tested`.

Framework markers and Brotli response encoding are not Node.js version or
decoder-exposure evidence. Keep offline version/inventory assessment free from
network requests and process execution. Preserve the collector's limited scope:
runtime metadata only, without environment variables, credentials, hostnames,
or application data.

Use local fixtures and mocks for meaningful behavior tests. Automated tests must
not scan external websites. Reduce real-world cases to synthetic examples
without personal data, cookies, tokens, or private URLs. Do not add tests that
only assert documentation wording.

Document CLI, schema, and output changes. Keep real lists, inventories, reports,
and credentials out of commits. Follow [AGENTS.md](AGENTS.md) for repository work.

## Licensing of contributions

node2shell-check follows the AGPL-3.0 / commercial licensing model described in
[LICENSING.md](LICENSING.md). By submitting a contribution, you confirm that you
have the right to submit it. You license it to the public under AGPL-3.0 and
grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license
to use, modify, sublicense, and distribute it under any license, including a
commercial license. You keep the copyright in your contribution.
