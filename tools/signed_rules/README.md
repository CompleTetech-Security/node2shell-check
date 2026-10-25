# Optional signed-rule bundle verification

This development tool verifies an **existing local TUF bundle** with maintained
[python-tuf 7.0.1](https://theupdateframework.readthedocs.io/en/latest/api/tuf.ngclient.updater.html).
It performs no network requests, executes no rules, and never changes the
checker's embedded snapshot. It produces an authenticated JSON artifact for
subsequent source review and a release build. Authentication does not establish
advisory accuracy, provenance of a reported runtime, or local exploitability.
The checker remains one file with no third-party dependencies.

## Trust recommendation and provisioning

CompleteTech should provision an offline Ed25519 root with a 2-of-3 threshold,
held by independent custodians, and separate targets, snapshot and timestamp
roles. Keep routine release keys separate from root custody. Production private
keys must never enter this repository, CI artifacts, reports, or support logs.
Ship the **public** root through an independently authenticated release channel
and record its SHA-256 in the release receipt. Do not trust a root merely because
it arrived beside an update. No production root, private key or automatic feed
is configured here. Tests generate ephemeral synthetic keys in memory.

Root replacement must satisfy both old and new root thresholds; rotate release
keys through authorized root metadata. A root compromise requires an independent
trust recovery procedure, rather than accepting a replacement supplied by the
untrusted bundle. The [TUF specification](https://theupdateframework.github.io/specification/latest/)
defines expiration, signature thresholds and rollback checks.

## Explicit offline use

Use an isolated environment; these optional crypto dependencies are justified
because implementing signature/trust logic ourselves would be unsafe.

```sh
python -m venv .venv-tuf
.venv-tuf/bin/python -m pip install -r tools/signed_rules/requirements.txt
.venv-tuf/bin/python tools/signed_rules/verify_bundle.py --help
.venv-tuf/bin/python tools/signed_rules/verify_bundle.py --bundle /existing/bundle --trusted-root /trusted/public-root.json --state /private/client-state --target node2shell-rules.json --output /review/new-rules.json
.venv-tuf/bin/python -m unittest discover -s tools/signed_rules -v
```

On Windows use `.venv-tuf\Scripts\python.exe`. The output parent and bundle must
already exist. A bundle has flat `metadata/` and `targets/` directories containing
standard TUF versioned metadata and hash-prefixed target files. Delegations are
not supported. The public root is a separate, explicitly pinned input.
Target names must be flat JSON filenames, and targets must decode to JSON objects.
No claims about a universal advisory schema are made: the subsequent reviewer
must validate the target against its particular checker's schema and primary
sources. A signed arbitrary JSON object is not an accepted detection rule.

All files read are limited to four MiB, new root rotations to 32 per invocation (in addition to authenticated cached
history replay), and delegation
traversal to zero. Bundle fetches use a local-only custom FetcherInterface; the
normal python-tuf HTTP fetcher, proxy behavior and retries are never used.
Symbolic links and path traversal in selected bundle paths are rejected. The
cache permits only python-tuf's own relative `root.json` convenience link into
its non-symlink `root_history/`; other cache links are rejected. Keep
bundle, root, state and output under directories controlled by the invoking user;
this is not a hostile concurrent filesystem sandbox.

## Failure, rollback and release procedure

Keep the state directory durable, private and dedicated to one original public
root. A create-exclusive lock prevents cooperating concurrent updates. Do not
delete the state directory or its metadata to bypass expiration or rollback
rejection. The bootstrap hash binds it to the exact originally provisioned root;
a differently serialized or replaced bootstrap is rejected. If a process is
killed without cleanup, verify that no updater still owns `update.lock` before
manually removing that lock only. Restore lost state from a trusted backup or
re-provision under the publisher's recovery procedure; this tool cannot detect
a hostile administrator deleting or rolling back its local state.

python-tuf persists verified metadata as verification advances, including when
a later step fails. Keeping this newer metadata prevents replay of older releases.
Failed signature/hash/length, expired metadata, missing targets, malformed JSON,
unknown publishers or rollback never replace an existing output. The verifier
exits 2 for errors (130 for interruption), writes only a generic failure message,
and retains embedded checker rules. Existing output requires explicit `--force`
and is replaced atomically only after verification. Rollback protection concerns
signed metadata versions; a trusted publisher can still intentionally sign older
content under a new version. Review changelog and advisory provenance before
releasing any rule change. Never use force or cache deletion as a rollback policy.

Release procedure: verify a local bundle; review the authenticated artifact's
schema, source links, uncertainty and thresholds; add boundary tests and dated
methodology; regenerate the embedded snapshot; obtain Copilot review and passing
CI for the exact commit; publish the normal checker release with a changelog.
Emergency rollback is a new reviewed, signed release with increasing metadata
versions. Failed updates leave the last released embedded rules available offline.

Tests cover real Ed25519 signatures, tampering, expiry, rollback, threshold-bound
root rotation, untrusted root/release keys, protected outputs and lock ownership.
They use synthetic data and prohibit socket creation. Production trust provisioning
and an authenticated hosted feed are operational work, not claimed delivered by
these fixtures.

Cached roots are replayed cryptographically from the original bootstrap on every
invocation. Their count is added to the new-rotation budget so routine root
rotations do not exhaust a lifetime limit. History is bounded to 4,096 regular
root files and 64 MiB; reaching that operational cap requires a publisher-planned
checkpoint/reprovisioning release, never bypassing verification or deleting cache.
