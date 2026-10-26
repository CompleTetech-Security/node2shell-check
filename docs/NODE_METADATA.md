# Optional Node.js family metadata

These tools support the one-repository-per-advisory roadmap. They do not combine
advisory scanners or change the Node2Shell CLI, schema 1 inventory, assessment
thresholds, dates or existing collector. Both collectors remain independently
usable by copying their own file. Use an explicitly trusted Node binary; this
project cannot attest that binary's vendor provenance or isolate hostile preload
hooks outside the collector. No application module is imported.

## Runtime and builtin capability report

```sh
node tools/collect-node-capabilities.cjs > node-capabilities.json
```

The distinct `node-capabilities/1` report contains an allowlist of Node/platform/
architecture metadata, OpenSSL/c-ares/Brotli/V8 version strings, TLS build feature
booleans, and builtin API availability for HTTP/2, TLS, DNS, Permission Model,
startup snapshots, SEA and Brotli. SEA's `isSea()` is the only queried builtin
function; other APIs are inspected by type and never invoked as tests. Unsupported
modules/API state remain null/unknown. The collector does not create sockets or
servers, resolve DNS, perform TLS, decompress data, build/load snapshots, enumerate
SEA assets, run shell commands, read application files or collect environment,
arguments, hostnames, credentials or application data. Build source remains unknown.

API availability is **not** application use, configuration, attacker-controlled
input, permission enforcement, mitigation, reachability or an advisory precondition.
The Permission API field does not attest active policy or its permissions. The
snapshot field does not identify the snapshot a process was started with. Library
versions do not establish Node cherry-pick/backport patch state. Runtime identity
is limited to the explicitly invoked collector process; it may differ from a
service's process. Reports keep application_use/reachability unknown and local
exploitability not_tested. Never automatically map a capability boolean to a
precondition in any of the advisory-specific checkers.

The old `collect-runtime.cjs` still emits exactly its schema 1 input accepted by
`node2shell_check.py --inventory`. The optional report is a separate evidence
artifact and is **not** accepted as that inventory. Continue using the old
collector for Node2Shell assessment; retain the new artifact for explicit
per-advisory review. No public schema or CLI migration is required.

Primary API references reviewed 2026-10-25:
[process.features](https://nodejs.org/api/process.html#processfeatures),
[Permission Model](https://nodejs.org/api/permissions.html),
[SEA isSea](https://nodejs.org/api/single-executable-applications.html#seaissea),
[HTTP/2](https://nodejs.org/api/http2.html), [TLS](https://nodejs.org/api/tls.html),
[DNS](https://nodejs.org/api/dns.html), [startup snapshots](https://nodejs.org/api/v8.html#startup-snapshot-api),
[Brotli](https://nodejs.org/api/zlib.html).

## Existing npm build context

```sh
python tools/inspect-node-build-context.py --input docs/examples/node-package-lock.json
python tools/inspect-node-build-context.py --help
```

Read an explicitly supplied package.json or npm lock v1/v2/v3 as JSON only.
`node-build-context/1` retains bounded `engines.node` declarations and relative
package paths. Version 2/3 use the primary packages map; version 1 traverses its
legacy dependency tree. This is compatibility/declaration context: even a plain
exact `engines.node` value is not the runtime that is installed or deployed. The
report always has an empty runtime_version, unknown runtime_state on observations,
and exploitability not_tested. Missing declarations establish no absence. Conflicts
at different package paths remain distinct; no range is solved into a runtime.

A narrow semver-range character vocabulary prevents arbitrary strings, URLs and
credentials from being echoed as declarations; unsupported strings become empty
unknown declarations. Registry URLs, resolved/integrity data, lifecycle scripts,
package names outside relative metadata paths and application contents are not
emitted or executed. Package paths themselves can be private; keep reports local.
No npm command, install, package load or network request occurs. These are metadata
artifacts for human review, not compatible scanner inventories or patch verdicts.

Limits: four MiB regular non-symlink input, supported lock versions only, depth 64,
100,000 visited package records, 512-character relative package paths, 10,000
observations and 256-character declarations. Duplicate JSON keys, invalid encoding,
malformed structures and limits fail with exit 2; interruption is 130 with no output
retry. JSON is ASCII escaped for portable redirected streams. Stdout is the only
output path; use shell redirection cautiously to avoid overwriting an input.

Primary format sources:
[npm package-lock](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/),
[npm engines](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#engines).

## Container and advisory integration

The optional [OCI inventory](https://github.com/CompleTetech-Security/oci-runtime-inventory)
reads existing image archives/SBOMs separately; it does not execute or pull images.
Node package observations and unverified provenance can be exported to the existing
Node2Shell inventory contract. A tag, manifest declaration or filesystem binary
name never supplies an exact runtime. Consult the named advisory matrix and each
checker's own embedded rules and precondition contract; none of these artifacts
attest a deployed application. The standalone scanners require no shared collector,
container tool, feed or installed runtime dependency for offline assessment.

Validation includes existing classification/collector regressions, guarded
synthetic Node VM fixtures that throw on sensitive property or active API access,
missing-module uncertainty, a local builtin report, lock v1/v2/v3 declarations,
malformed inputs, bounds and privacy. Hosted jobs explicitly install Node 24 so
collector checks run; the Python checker itself remains standard-library-only.
