# Node2Shell Check: full reference

`node2shell_check.py` is a standard-library-only Python 3.10+ checker for
version-based CVE-2026-111497 exposure triage. It supports Windows, macOS, and
Linux. No Python package installation, API key, database, or browser is required.

## Inputs

You may combine all three input modes in a single run. Each input creates a
separate observation; a supplied runtime version is not assumed to belong to a
supplied URL.

### Website URLs

```sh
python node2shell_check.py https://example.com example.org
python node2shell_check.py --input websites.txt --format json --output websites.json
```

Text input files are UTF-8, one domain or HTTP(S) URL per line. Blank lines and
lines starting with `#` are ignored. A UTF-8 BOM is accepted. The included
`websites.example.txt` uses reserved example domains. Replace those entries with
targets you are authorized to assess.

Bare domains default to HTTPS. Paths are checked as supplied; there is no crawl
or endpoint enumeration. URLs with credentials are rejected. There is no HTTP
fallback after a TLS error. Exact duplicate URL inputs are skipped.
URL input files are limited to 4 MiB. The combined run is limited to 10,000
observations across URLs, supplied versions, and inventory entries.

### Reported Node.js versions

```sh
python node2shell_check.py --node-version v22.23.3 --node-version 24.22.1
```

`--node-version` is repeatable and operates offline. It accepts complete runtime
version strings, including the conventional leading `v`. Build qualifiers,
prereleases, partial values, and malformed values remain uncertain. The checker
does not invoke Node.js to obtain a value for you.

### Collector inventory

Run the optional collector in the relevant runtime or container:

```sh
node collect-runtime.cjs > runtime.json
python node2shell_check.py --inventory runtime.json --format json --output assessment.json
```

`--inventory` is repeatable. Each file accepts one collector-compatible JSON
object or an array of such objects with `schema_version` set to `1`. Use the
collector output as the schema example. Unsupported schema versions and invalid
inventory data are operational errors; do not reinterpret arbitrary JSON as a
verified runtime inventory.

| Inventory field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | Integer | `1` for this format. |
| `runtime` | String | `node`; other runtimes require their own assessment. |
| `label` | String | Optional human-readable identity; collector default is `local-node`. |
| `node_version` | String | Required reported runtime version. |
| `build_source` | String | Provenance reported by the operator; collector default is `unknown`. |
| `brotli_version` | String | Reported bundled Brotli version; contextual metadata, not a patch verdict. |
| `brotli_decompress_available` | Boolean or null | Whether the collector found all three standard Brotli decompression APIs. |
| `brotli_block_switch_error` | Integer or null | Reported value of the decoder's block-switch error constant, if present. |
| `platform` | String | Runtime platform. |
| `architecture` | String | Runtime architecture. |

Only these fields are accepted. Unknown fields, duplicate JSON keys, non-finite
JSON numbers, incorrect types, files over 4 MiB, and arrays outside 1–10,000
entries are rejected. String fields are limited to 512 characters. These bounds
apply before runtime-version comparison.

Build-source values `unknown`, `upstream`, `official`, and `official_upstream`
permit the ordinary version comparison; they are operator claims, not verified
provenance. A reported vendor, distribution, custom, or unrecognized source
keeps the result `unknown`. Do not label a vendor package as official merely to
obtain a comparison result.

The collector records only runtime/build metadata. It does not collect
hostnames, environment variables, tokens, application files, or process
arguments. Its `build_source` defaults to `unknown`; that metadata does not
constitute vendor patch attestation. Inventory assessment makes no network
requests and does not execute the collector or application.

Keep real inventories and assessment reports outside version control.

## CLI options

| Argument | Default | Description |
| --- | --- | --- |
| `urls` | None | HTTP(S) website URLs or bare domains. |
| `--input PATH` | None | UTF-8 file containing one authorized website per line. |
| `--node-version VERSION` | None | Offline version comparison; repeatable. |
| `--inventory PATH` | None | Read collector-compatible JSON; repeatable. |
| `--format csv\|json\|html` | `csv` | Output format. |
| `--output PATH` | stdout | Write results to a file. Existing files are refused unless `--force` is supplied. |
| `--force` | Off | Allow replacement of an existing output file. |
| `--brand NAME` | `CompleteTech LLC` | Organization name displayed in the HTML report. |
| `--logo PATH` | `assets/logo.png` | PNG, JPEG, GIF, or WebP logo, at most 1 MiB, embedded into the HTML report. |
| `--delay SECONDS` | `1` | Minimum request spacing; positive, at most 60 seconds. Robots policy may increase spacing. |
| `--timeout SECONDS` | `15` | Socket timeout/body-read deadline; positive, at most 60 seconds. This is not a whole-run deadline. |
| `--contact VALUE` | Empty | Public contact URL/email included in the descriptive User-Agent. ASCII only; control characters are rejected. |
| `--fail-on-finding` | Off | Exit with code 1 when results include `potentially_affected` or `unsupported_runtime`, unless an operational error takes precedence. |
| `--version` | — | Display checker version. |
| `--help` | — | Display command usage. |

On systems where Python is called `python3`, substitute it in the examples.
The standalone checker file works without the repository logo; report branding
can be supplied with `--logo` and `--brand`.

## Assessment statuses

| Status | Meaning |
| --- | --- |
| `potentially_affected` | A comparable plain Node.js version is below its branch's upstream fix. |
| `fixed_version_reported` | The reported version meets the branch's fix threshold. |
| `unsupported_runtime` | An older unsupported upstream runtime needs upgrade/vendor review. |
| `unknown` | Version evidence is missing, conflicting, malformed, qualified, custom, prerelease, or uncovered. |

Every assessment sets exploitability to `not_tested`. A fetched page, framework
hint, response compression header, or successful inventory read does not confirm
vulnerability or absence of exposure. See [NODE2SHELL.md](NODE2SHELL.md) for the
dated fix table and interpretation rules.

## Output formats

### CSV

CSV contains flat result rows with explicit evidence, assessment, and operational
fields. Array values are represented as readable text. Strings that could become
spreadsheet formulas are prefixed with an apostrophe. Progress and diagnostic
messages go to stderr, leaving stdout available for data.

Report schema `1.1` preserves every existing result-column position
and appends `tool`, `tool_version`, `tool_sha256`, `report_schema_version`,
`generated_at`, `complete`, and `record_type`. `complete` is lowercase `true` or
`false`; `record_type=result` identifies an observation. Empty runs have one
`record_type=summary` row carrying build identity, rule date, completeness and
`not_tested`, with no fabricated target. Consumers must distinguish summaries
from observations. An interrupted zero-result CSV is therefore self-describing.
The classifier's `tool_version` remains `1.0.0` for existing named-adapter
compatibility; the additive report schema and exact executable digest identify
this changed export. Existing bridge profile `node2shell-v1` still accepts its
JSON; retain the original report for the new top-level provenance fields, which
that older converter does not project. Classification thresholds are unchanged.

### JSON

JSON is an object with these top-level fields:

| Field | Meaning |
| --- | --- |
| `tool` | Checker name. |
| `tool_version` | Checker version used for the run. |
| `tool_sha256` | SHA-256 of this standalone executable's exact bytes, captured at startup. Not a publisher signature. |
| `report_schema_version` | Additive output contract, currently `1.1`; inventory schema remains `1`. |
| `rules_as_of` | Date of the embedded assessment rules. |
| `generated_at` | Report generation timestamp. |
| `complete` | Whether all requested observations completed. Inspect individual operational outcomes as well. |
| `results` | Array of result objects, preserving structured evidence. |

This envelope differs from the bare result array used by `php2shell-check`.
An interruption handled by the checker keeps completed observations and marks
the report incomplete. `complete: true` means the input loop finished; it does
not mean every HTTP request succeeded or every version was identified.
The timestamp and rule date serve different purposes: rerunning an old checker
does not update its rules.

### HTML

HTML is a single offline report with an embedded local logo, summary counts,
assessment details, remediation guidance, fixed-version thresholds, source links,
and run-completeness information. Its footer identifies the tool version, report
schema and executable SHA-256 even for empty reports. Observation `checked_at`,
report `generated_at`, and rules verification date retain distinct meanings.
It supports dark/light themes and printing.
Dynamic text is escaped; the document contains no scripts or remotely loaded
assets. The checked website URLs are evidence, not resources fetched by the
report.

Use a fresh output path for a new report. `--force` deliberately replaces an
existing file; preserve any earlier evidence you need before using it.

File output is prepared in a temporary file in the destination directory, then
published atomically. By default publication uses a hard link to avoid replacing
a file created concurrently; the destination filesystem must support hard
links. An unsupported filesystem produces an output error rather than silently
weakening overwrite protection. With `--force`, publication uses atomic
replacement instead. The output directory must already exist. Input and logo
files cannot be used as the output destination, including with `--force`.

The checker writes the report after the input loop or a handled keyboard
interruption. Abrupt termination, process crashes, or power loss before that
point can prevent report creation. It does not implement incremental checkpoints
or automatic resume. CSV now carries run completeness on every result or empty
summary row; retain the exit status/stderr as separate operational evidence.

## Requests made in website mode

1. Validate and normalize the supplied HTTP(S) URL.
2. Fetch the origin's `/robots.txt`.
3. Evaluate applicable robots rules and request spacing.
4. GET the supplied page if permitted, checking policy at allowed redirects.
5. Inspect returned headers and available HTML. Linked assets are not fetched.

Network requests are sequential. TLS certificate verification remains enabled.
The checker uses a descriptive User-Agent and requests `Accept-Encoding:
identity`. It never sends Brotli payloads or decompresses responses. There are
no automatic retries or access-control bypasses. Proxy environment variables
are ignored; connections are direct through the operating system network stack.

Robots handling supports user-agent groups, Allow/Disallow rules, wildcards,
end anchors, and common crawl-delay/request-rate hints. A missing policy with
HTTP 404/410 permits the page check. An inaccessible, truncated, compressed, or
HTML policy stops it. Permissive robots policy does not itself confer permission
to assess a website.

Redirects are limited to five hops and the same host or its `www` counterpart.
HTTPS-to-HTTP downgrades stop. Redirects do not authorize a wider crawl. Page
reads are bounded at 2 MiB and robots reads at 512 KiB. Robots policies requiring
more than 60 seconds of spacing stop the page check rather than being ignored.

HTTP restrictions, network failures, uncertain body encodings, and truncation
are recorded as operational/evidence limitations. No option disables TLS
verification or skips robots policy.

## Local use and service boundaries

Private and loopback addresses are supported for authorized internal assessment.
The program is a local CLI/library, not a service designed to accept untrusted
arbitrary URLs. Hosting it behind a website would require separate authorization,
network isolation, destination controls, queue limits, and data-handling design.

There is no telemetry or automatic upload destination. Website mode necessarily
contacts the supplied targets and their permitted redirects. Reports can contain
target URLs, response metadata, and operator-supplied inventory; handle them as
assessment records.

## Exit codes and incomplete work

| Code | Meaning |
| --- | --- |
| `0` | Run completed without an operational error; findings do not change this unless `--fail-on-finding` is enabled. |
| `1` | `--fail-on-finding` was enabled and at least one potentially affected or unsupported runtime was reported. |
| `2` | Argument/input/output error or operational failure prevented one or more requested checks. |
| `130` | Run interrupted; completed observations are retained where output can be written. |

Unknown assessment evidence is not automatically an operational error. An
otherwise successful request may legitimately reveal no runtime version.
Conversely, a fixed-version observation elsewhere in the report does not erase
an unsuccessful website check. Inspect both per-result outcomes and report
completeness.

## Result fields

The same result model is used in every format. JSON preserves arrays and nulls;
CSV renders arrays as readable text. Empty version strings mean missing or
conflicting evidence, not version zero.

| Field | Meaning |
| --- | --- |
| `input_url` | Supplied website or identity of an offline version/inventory observation; the historical-style name does not imply every row is a URL. |
| `final_url` | Last/final page URL for a website check; empty for offline observations. |
| `source` | `http`, `version`, or `inventory`. |
| `status` | Evidence/detection outcome, separate from the security assessment. |
| `fetch_status` | Network outcome, or `not_requested` for offline input. |
| `http_status` | Last page HTTP status, if available. |
| `node_version` | One explicit reported Node.js version, or empty if absent/conflicting. |
| `node_version_candidates` | Distinct explicit runtime-version disclosures. |
| `node_evidence` | Headers or operator-supplied provenance supporting the observation. |
| `framework_hints` | Framework indicators that do not establish Node.js identity or version. |
| `server`, `powered_by` | Public `Server` and `X-Powered-By` response headers. |
| `title` | Observed HTML title, at most 500 characters. |
| `response_brotli` | Whether the response advertised Brotli encoding; not request-decoder evidence. |
| `build_source` | Reported runtime build provenance. |
| `brotli_version` | Reported decoder-library version; not an independent patch check. |
| `brotli_decompress_available` | Reported API availability, if provided. |
| `brotli_block_switch_error` | Reported decoder constant, if provided. |
| `platform`, `architecture` | Runtime metadata supplied in inventory. |
| `notes` | Operational restrictions and general evidence limitations. |
| `checked_at` | Observation timestamp in UTC. |
| `node2shell_status` | One of the four assessment statuses described above. |
| `node2shell_version_status` | Detailed reason for the version interpretation. |
| `node2shell_fixed_version` | Applicable upstream branch fix, when covered. |
| `node2shell_exploitability` | Always `not_tested`. |
| `node2shell_cves` | Covered CVE identifiers. |
| `node2shell_rules_as_of` | Embedded rule-snapshot date. |
| `node2shell_sources` | Primary source URLs used for the assessment. |
| `node2shell_notes` | Assessment reasoning and uncertainty. |
| `node2shell_recommendation` | Administrator verification/remediation guidance. |

Evidence `status` values are `node_detected`, `framework_hint`, `no_evidence`,
`offline`, `blocked`, and `error`. `node_detected` means a Node-related disclosure
was observed, not that the checker independently identified the server process.
`framework_hint` and `no_evidence` do not produce an absence/safety conclusion.

`fetch_status` uses `ok`, `timeout`, `dns_error`, `blocked`, or `not_requested`.
The coarse `blocked` value includes unsuccessful cases such as invalid input or
TLS failure; it does not prove that an owner deliberately blocked the checker.
Use `notes` and `http_status` for the precise context.

## Development checks

```sh
python -m unittest -v
python node2shell_check.py --help
git diff --check
```

Automated Python tests use synthetic metadata, mocks, and loopback HTTP fixtures.
They do not call external websites. GitHub Actions runs the suite on Linux and
Windows with Python 3.10 and 3.14. See [CONTRIBUTING.md](../CONTRIBUTING.md).
