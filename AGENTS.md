# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
[SECURITY.md](SECURITY.md) before changing this project.

## Project map

- `node2shell_check.py`: standalone Python 3.10+ CLI, passive fetcher, offline
  version/inventory assessment, and CSV/JSON/HTML rendering.
- `collect-runtime.cjs`: optional Node.js metadata collector; emits schema v1
  inventory without loading application code or decompressing data.
- `test_*.py`: focused local-only behavior tests.
- `docs/NODE2SHELL.md`: dated, source-linked classification methodology.
- `docs/REFERENCE.md`: CLI, inventory, outputs, and network behavior.
- `docs/example-report.html`: synthetic example; never replace with real data.
- `docs/CHECKER_FAMILY.md`: one-repository-per-exploit roadmap for related checkers.
- `.github/workflows/tests.yml`: Python checks on Linux and Windows.

## Implementation constraints

Keep the Python checker usable as one file without third-party runtime or test
dependencies. Preserve verified TLS, robots policy, descriptive User-Agent,
pacing, response-size bounds, conservative redirects, and no environment-proxy
inheritance. Do not add payload probes, authentication bypasses, automatic
retries around access restrictions, or external requests to offline modes.
Editing code and running tests do not authorize scanning real websites.

Reported versions are evidence, not verified runtime state. Keep missing,
conflicting, malformed, prerelease, vendor/custom-build, and uncovered-future
cases uncertain. Preserve `unsupported_runtime` as an upgrade/review result.
Never present `potentially_affected` as confirmed exploitability or
`fixed_version_reported` as a safety guarantee. Exploitability remains
`not_tested`. Framework hints and response Brotli encoding must not be converted
into Node.js version or request-decoder exposure evidence.

Keep the collector limited to runtime/build metadata. Do not collect hostnames,
environment variables, credentials, process arguments, or application data.
It cannot attest vendor patch provenance; keep its default build source unknown.

Update the fix table and rule date only after verifying official sources. Update
focused boundary tests and methodology together. Keep CLI, schema, README, and
reference documentation aligned. Preserve valid completed-result output after
interruptions and avoid silent overwriting of existing reports.

## Validation and delivery

```sh
python -m unittest -v
python node2shell_check.py --help
git diff --check
```

Use mocks, synthetic inventories, and loopback HTTP fixtures. Do not contact
external targets in tests or add tests merely asserting prose. Check
documentation commands against real help/source and verify referenced paths.

Use focused changes, preserve unrelated work, and keep real targets, inventories,
reports, workbooks, and secrets out of commits. Verify hosted CI for the actual
published commit when available; report local checks and hosted CI separately.
Repository creation does not authorize publishing private assessment data.
Follow [LICENSING.md](LICENSING.md) and [BRAND_ASSETS.md](BRAND_ASSETS.md).
