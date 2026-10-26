# Authenticated rule publication

The project uses GitHub Actions OIDC and Sigstore artifact attestations for its
optional production rule-distribution channel. This adopts existing company
repository control rather than requiring three new offline key custodians.
The optional operator-managed TUF verifier remains available separately.

## Trust policy

Install the checker/tool and GitHub CLI through independently trusted channels.
The verifier pins `CompleTetech-Security/node2shell-check`, repository ID
`1431446570`, owner ID `347271566`, GitHub's OIDC issuer, and the exact
`.github/workflows/publish-rules.yml@refs/heads/main` certificate identity.
Source and signer commit digests must equal the authenticated envelope's commit;
self-hosted runners are rejected. Repository rename/recreation is not silently
accepted. Never obtain a replacement verifier or trust policy from the update
being verified. These checks use maintained `gh attestation verify`, not custom
cryptography. GitHub CLI with all documented attestation policy flags is required
(validated locally with 2.92.0).

Trust the Sigstore CA/transparency roots obtained independently through
`gh attestation trusted-root`, not roots supplied beside the artifact. Refresh
those roots through that same trusted channel when importing newly signed
material. Sigstore rotates its signing infrastructure; old offline roots cannot
inform you of later revocations. See GitHub's
[offline verification guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
and [CLI policy reference](https://cli.github.com/manual/gh_attestation_verify).

## Publisher and recovery ownership

The company's repository administrators maintain publishing access, review the
workflow and source changes, and own compromise recovery. This adopts the
existing repository-admin role; no named human custodian is invented. GitHub
Actions obtains a short-lived signing identity per run. No persistent project
signing private key is generated, installed on this workstation or stored in CI.
The trust boundary includes GitHub, Sigstore, repository administrators, the
reviewed workflow and the trusted local GitHub CLI.

An authorized maintainer explicitly dispatches **Publish authenticated rule
snapshot** on `main`. The job runs local-only tests, packages the existing
embedded snapshot, attests those exact bytes and creates a new release with
`node2shell-rules.json` and `node2shell-rules.sigstore.json`. Tags have the form
`rules-v1-RUN_NUMBER-ATTEMPT`; no existing release/asset is overwritten and no
unrelated software release is marked latest. There is no recurring schedule.
Each dispatch is a release decision. Review advisory provenance and methodology
before changing thresholds; republishing does not change the embedded rule date.

Envelopes expire after 30 days. Sequence is `RUN_NUMBER * 1000 + ATTEMPT`, with
attempts below 1,000. Rerunning an old run cannot outrank a newer run. Preserve
workflow history/counters; deleting/recreating the workflow is not a recovery
mechanism. A rollback of rule content must be a new reviewed publication with
an increasing sequence and a changelog explaining the older content.

For compromise, disable publishing and revoke unauthorized repository access.
Investigate the source/workflow and publish a reviewed recovery tool/policy
through an independent trusted channel. Existing offline envelopes may remain
valid until expiry; disabling a workflow does not remotely revoke cached files.
Do not reset client state to accept an older sequence. A repository transfer,
new numeric identity or a counter reset requires an explicit reviewed policy
migration and independently distributed recovery instructions. Operator-managed
offline TUF threshold roots remain an alternative for organizations requiring
independent offline publisher custody; they are not claimed provisioned here.

## Explicit client operation

Select an exact release tag from the repository's authenticated release history.
The following provisioning/download commands use the network intentionally;
replace `rules-v1-N-A` with that exact tag and use new output directories:

```sh
mkdir downloaded-rules
gh release download rules-v1-N-A --repo CompleTetech-Security/node2shell-check --dir downloaded-rules
python -c "import pathlib,subprocess; pathlib.Path('sigstore-trusted-root.jsonl').write_bytes(subprocess.check_output(['gh','attestation','trusted-root']))"
python tools/signed_rules/keyless_rules.py verify --artifact downloaded-rules/node2shell-rules.json --bundle downloaded-rules/node2shell-rules.sigstore.json --trusted-root sigstore-trusted-root.jsonl --state client-rule-state.json --output verified-rule-review.json
```

The verification command consumes local files only; GitHub CLI receives both
`--bundle` and `--custom-trusted-root`. It checks the signature, artifact digest,
certificate identity and source commit before the tool publishes output. Inputs
and verifier output are bounded to four MiB; the child verifier has a timeout.
Keep these files/directories controlled by the invoking user: this is not a
hostile concurrent-filesystem sandbox. Do not share the private client state.

Duplicate/nonfinite/invalid JSON, wrong publisher/source, expired/future releases,
malformed snapshots, older sequences and sequence reuse with different bytes
fail closed. An identical verified artifact can be retried. State advances before
output publication so a failed output cannot enable a replay; the old output
survives. Keep durable state and backups. A detected backward clock fails closed.
Deleting or restoring an old state manually defeats rollback protection and is
not automatic recovery. Remove an abandoned `.lock` only after proving its
process is no longer running. New output names are required unless `--force`
is supplied; hard-link support is required for no-clobber publication. Errors
exit 2, interruption exits 130 and is never retried automatically.

The output is a rule snapshot for source review and a later normal release
build. It does not install or execute rules, update a running checker, prove
advisory accuracy, attest a runtime, or turn metadata into a safety verdict.
All local exploitability remains `not_tested`. Signature success and expiry do
not prove you selected the newest release on first use; select the release
through the trusted repository channel and retain state for later updates.
