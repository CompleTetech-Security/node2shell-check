#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Optional release-artifact verification; never changes the checker or fetches rules."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPOSITORY = "CompleTetech-Security/node2shell-check"
REPOSITORY_ID = "1431446570"
OWNER_ID = "347271566"
WORKFLOW = REPOSITORY + "/.github/workflows/publish-rules.yml"
IDENTITY = "https://github.com/" + WORKFLOW + "@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
MAX_BYTES = 4 * 1024 * 1024


def read_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a bounded regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input exceeds four MiB")
    return raw


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid number")))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def stamp(value):
    if not isinstance(value, str):
        raise ValueError("Invalid timestamp")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def timestamp(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate(value, now):
    keys = {"schema", "sequence", "issued_at", "expires_at", "source_commit", "rules"}
    if not isinstance(value, dict) or set(value) != keys or value["schema"] != "node2shell-rules/1":
        raise ValueError("Unsupported release envelope")
    if type(value["sequence"]) is not int or not 1 <= value["sequence"] <= 10**15:
        raise ValueError("Invalid release sequence")
    if not isinstance(value["source_commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", value["source_commit"]):
        raise ValueError("Invalid source commit")
    issued, expires = stamp(value["issued_at"]), stamp(value["expires_at"])
    if issued > now + timedelta(minutes=5) or expires <= now or not issued < expires <= issued + timedelta(days=31):
        raise ValueError("Expired, future or excessive release validity")
    rules = value["rules"]
    if not isinstance(rules, dict) or set(rules) != {"cves", "as_of", "fixes", "sources", "exploitability", "checker_sha256"}:
        raise ValueError("Unsupported rule snapshot")
    if rules["exploitability"] != "not_tested" or not isinstance(rules["checker_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", rules["checker_sha256"]):
        raise ValueError("Invalid snapshot evidence")
    if not isinstance(rules["cves"], list) or not 1 <= len(rules["cves"]) <= 32 or any(not isinstance(c, str) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,10}", c) for c in rules["cves"]):
        raise ValueError("Invalid advisory identifiers")
    if not isinstance(rules["as_of"], str) or datetime.strptime(rules["as_of"], "%Y-%m-%d").date() > issued.date():
        raise ValueError("Invalid rule date")
    fixes = rules["fixes"]
    if not isinstance(fixes, dict) or not 1 <= len(fixes) <= 32:
        raise ValueError("Invalid fix table")
    for major, version in fixes.items():
        if not re.fullmatch(r"[1-9][0-9]{0,2}", major) or not isinstance(version, list) or len(version) != 3 or any(type(n) is not int or not 0 <= n <= 999999 for n in version) or version[0] != int(major):
            raise ValueError("Invalid fix boundary")
    if not isinstance(rules["sources"], list) or not 1 <= len(rules["sources"]) <= 32 or any(not isinstance(s, str) or len(s) > 512 or not re.fullmatch(r"https://nodejs\.org/[A-Za-z0-9_./-]+", s) for s in rules["sources"]):
        raise ValueError("Invalid primary-source links")
    return value


def build(sequence, commit, now=None):
    now = now or datetime.now(timezone.utc)
    script = Path(__file__).resolve().parents[2] / "node2shell_check.py"
    spec = importlib.util.spec_from_file_location("release_checker", script)
    checker = importlib.util.module_from_spec(spec)
    # dataclasses consult sys.modules while the trusted repository module loads.
    import sys
    sys.modules[spec.name] = checker
    spec.loader.exec_module(checker)
    value = dict(schema="node2shell-rules/1", sequence=sequence, source_commit=commit,
                 issued_at=timestamp(now), expires_at=timestamp(now + timedelta(days=30)),
                 rules=dict(cves=list(checker.NODE2SHELL_CVES), as_of=checker.NODE2SHELL_RULES_DATE,
                            fixes={str(k): list(v) for k, v in checker.NODE2SHELL_FIXES.items()},
                            sources=list(checker.NODE2SHELL_SOURCES), exploitability="not_tested",
                            checker_sha256=hashlib.sha256(script.read_bytes()).hexdigest()))
    return validate(value, now)


def verify_provenance(artifact, bundle, root, commit):
    gh = shutil.which("gh")
    if not gh:
        raise ValueError("Install a trusted GitHub CLI with attestation support")
    command = [gh, "attestation", "verify", str(artifact), "--repo", REPOSITORY,
               "--bundle", str(bundle), "--custom-trusted-root", str(root),
               "--signer-workflow", WORKFLOW, "--cert-identity", IDENTITY,
               "--cert-oidc-issuer", ISSUER, "--source-ref", "refs/heads/main",
               "--source-digest", commit, "--signer-digest", commit,
               "--deny-self-hosted-runners", "--hostname", "github.com", "--format", "json"]
    # Both bundle and independently sourced root are explicit local inputs.
    # No shell, release lookup, default HTTP fetcher, or rule execution is used.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                       timeout=120, check=True)
        out.seek(0)
        results = decode(out.read(MAX_BYTES + 1))
    if not isinstance(results, list) or not 1 <= len(results) <= 30:
        raise ValueError("Missing verified provenance")
    for result in results:
        cert = result["verificationResult"]["signature"]["certificate"]
        if cert.get("sourceRepositoryIdentifier") != REPOSITORY_ID or cert.get("sourceRepositoryOwnerIdentifier") != OWNER_ID:
            raise ValueError("Publisher numeric identity mismatch")


def atomic(path, data, replace=False):
    fd, name = tempfile.mkstemp(prefix=".rules-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path)
        else:
            os.link(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def verify(artifact, bundle, root, state, output, force=False, now=None):
    now = now or datetime.now(timezone.utc)
    paths = [Path(p).absolute() for p in (artifact, bundle, root, state, output)]
    if any(p.is_symlink() for p in paths):
        raise ValueError("Links are not accepted")
    artifact, bundle, root, state, output = [p.resolve() for p in paths]
    lock = state.with_name(state.name + ".lock")
    protected = [artifact, bundle, root, Path(__file__).resolve(),
                 Path(__file__).resolve().parents[2] / "node2shell_check.py", lock]
    if not output.parent.is_dir() or state in protected or output in protected or output == state:
        raise ValueError("Protected output/state paths")
    if state.exists() and any(os.path.samefile(state, p) for p in protected if p.exists()):
        raise ValueError("State aliases an input")
    if output.exists() and (not force or any(os.path.samefile(output, p) for p in [*protected, state] if p.exists())):
        raise ValueError("Output exists or aliases protected input")
    if not state.parent.is_dir():
        raise ValueError("State parent must exist")
    raw = read_file(artifact)
    read_file(bundle)
    read_file(root)
    value = validate(decode(raw), now)
    digest = hashlib.sha256(raw).hexdigest()
    # Verify the exact staged bytes, avoiding a change between parsing and gh.
    with tempfile.TemporaryDirectory(prefix="keyless-rules-") as directory:
        staged = Path(directory) / "node2shell-rules.json"
        staged.write_bytes(raw)
        verify_provenance(staged, bundle, root, value["source_commit"])
    # Ownership is established only after exclusive creation succeeds.
    with lock.open("xb"):
        pass
    try:
        if state.exists():
            prior = decode(read_file(state))
            if not isinstance(prior, dict) or set(prior) != {"policy", "sequence", "sha256", "accepted_at"} or prior["policy"] != REPOSITORY_ID + ":keyless-v1" or type(prior["sequence"]) is not int or not 1 <= prior["sequence"] <= 10**15 or not isinstance(prior["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", prior["sha256"]):
                raise ValueError("Invalid durable state")
            if now < stamp(prior["accepted_at"]) - timedelta(minutes=5):
                raise ValueError("Clock rollback")
            if value["sequence"] < prior["sequence"] or (value["sequence"] == prior["sequence"] and digest != prior["sha256"]):
                raise ValueError("Release rollback or sequence reuse")
        # Fence replay before publishing. Same-artifact retry is allowed after
        # output failure; cache deletion is never an automatic recovery action.
        atomic(state, encoded(dict(policy=REPOSITORY_ID + ":keyless-v1", sequence=value["sequence"], sha256=digest, accepted_at=timestamp(now))), replace=state.exists())
        atomic(output, encoded(value["rules"]), replace=force)
        return digest
    finally:
        lock.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    publisher = sub.add_parser("build", help="Build metadata from this trusted checkout; no signing")
    publisher.add_argument("--sequence", type=int, required=True)
    publisher.add_argument("--commit", required=True)
    publisher.add_argument("--output", type=Path, required=True)
    consumer = sub.add_parser("verify", help="Verify existing local artifact/bundle with independent Sigstore roots")
    for name in ("artifact", "bundle", "trusted-root", "state", "output"):
        consumer.add_argument("--" + name, type=Path, required=True)
    consumer.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            if args.output.resolve() == Path(__file__).resolve() or args.output.is_symlink():
                raise ValueError("Protected build output")
            atomic(args.output, encoded(build(args.sequence, args.commit)))
        else:
            verify(args.artifact, args.bundle, args.trusted_root, args.state, args.output, args.force)
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        import sys
        print("Rule artifact rejected or publication failed; existing checker rules remain unchanged.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
