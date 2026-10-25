#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Optional offline TUF bundle verification. Never imports the checker or rules."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

MAX_BYTES = 4 * 1024 * 1024
BASE = 'https://offline.invalid/'


def read_bounded(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular file')
    with path.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('File exceeds four MiB')
    return data


def atomic_write(path, data, *, replace=False):
    fd, name = tempfile.mkstemp(prefix='.verified-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(name, path)
        else:
            os.link(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def exclusive_lock(path):
    with path.open("xb"):
        pass
    try:
        yield
    finally:
        path.unlink()


def verify(bundle, root, state, output, target, force=False):
    # Optional dependency: only this explicitly invoked tool imports it.
    from tuf.ngclient import Updater, UpdaterConfig
    from tuf.ngclient.fetcher import FetcherInterface
    from tuf.api.exceptions import DownloadHTTPError

    class BundleFetcher(FetcherInterface):
        def _fetch(self, url):
            parsed = urlsplit(url)
            # python-tuf generates versioned metadata and hash-prefixed targets.
            # Only flat literal names are accepted; no URL decoding or filesystem traversal.
            if parsed.scheme != 'https' or parsed.netloc != 'offline.invalid' or parsed.query or parsed.fragment:
                raise ValueError('Non-local bundle request rejected')
            match = re.fullmatch(r'/(metadata|targets)/([A-Za-z0-9_.-]{1,240})', parsed.path)
            if not match or match[2] in ('.', '..'):
                raise ValueError('Unsupported bundle path')
            directory = bundle / match[1]
            if directory.is_symlink():
                raise ValueError('Bundle links are not accepted')
            path = directory / match[2]
            if not path.exists():
                raise DownloadHTTPError('No such bundle member', 404)
            yield read_bounded(path)

    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.json', target):
        raise ValueError('Target must be a flat JSON filename')
    bundle, root, state, output = map(lambda p: p.absolute(), (bundle, root, state, output))
    if bundle.is_symlink() or root.is_symlink() or state.is_symlink() or output.is_symlink():
        raise ValueError('Links are not accepted for bundle, state or output')
    bundle, root, state, output = map(lambda p: p.resolve(), (bundle, root, state, output))
    if not bundle.is_dir() or not output.parent.is_dir():
        raise ValueError('Bundle and output parent must already exist')
    if output == root or output.is_relative_to(bundle) or output.is_relative_to(state):
        raise ValueError('Output must be separate from trust root, bundle and state')
    if state.is_relative_to(bundle) or bundle.is_relative_to(state) or root.is_relative_to(state):
        raise ValueError('State, bundle and pinned root must be separate')
    if output.exists() and (not force or os.path.samefile(output, root)):
        raise ValueError('Output exists or aliases pinned root; choose another output')
    bootstrap = read_bounded(root)
    # The root is an operator-provisioned trust anchor, never taken from bundle metadata.
    anchor = hashlib.sha256(bootstrap).hexdigest().encode('ascii') + b'\n'
    state.mkdir(mode=0o700, parents=False, exist_ok=True)
    lock = state / 'update.lock'
    with exclusive_lock(lock):
        marker = state / 'bootstrap.sha256'
        if marker.exists():
            if read_bounded(marker) != anchor:
                raise ValueError('State is bound to another bootstrap root')
        else:
            # Do not adopt preexisting metadata with an unrecorded trust history.
            if any(p.name != 'update.lock' for p in state.iterdir()):
                raise ValueError('Uninitialized state must be empty')
            atomic_write(marker, anchor)
        cache = state / 'metadata'
        cache.mkdir(exist_ok=True)
        if cache.is_symlink() or any(p.is_symlink() for p in cache.iterdir()):
            raise ValueError('Metadata cache links are not accepted')
        updater = Updater(str(cache), BASE + 'metadata/',
                          fetcher=BundleFetcher(), bootstrap=bootstrap,
                          config=UpdaterConfig(max_root_rotations=32, max_delegations=0,
                                               root_max_length=MAX_BYTES,
                                               timestamp_max_length=MAX_BYTES,
                                               snapshot_max_length=MAX_BYTES,
                                               targets_max_length=MAX_BYTES))
        updater.refresh()
        info = updater.get_targetinfo(target)
        if info is None or info.length > MAX_BYTES:
            raise ValueError('Target missing or oversized')
        # Updater verifies target length/hash; temporary verified bytes never run.
        with tempfile.TemporaryDirectory(prefix='target-', dir=state) as directory:
            path = Path(directory) / 'verified.json'
            updater.download_target(info, str(path), BASE + 'targets/')
            data = read_bounded(path)
            try:
                value = json.loads(data, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON")))
            except (ValueError, RecursionError) as exc:
                raise ValueError('Verified target is not bounded JSON') from exc
            if not isinstance(value, dict):
                raise ValueError('Verified target must be a JSON object')
            atomic_write(output, data, replace=force)
        return hashlib.sha256(data).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True, help='Existing offline TUF metadata/ and targets/ directories')
    parser.add_argument('--trusted-root', type=Path, required=True, help='Independently provisioned public root.json')
    parser.add_argument('--state', type=Path, required=True, help='Persistent private rollback cache; never reset to bypass rejection')
    parser.add_argument('--target', required=True, help='Explicit flat JSON target filename')
    parser.add_argument('--output', type=Path, required=True, help='New verified JSON artifact; never automatically applied')
    parser.add_argument('--force', action='store_true', help='Replace output only after successful verification')
    args = parser.parse_args(argv)
    try:
        digest = verify(args.bundle, args.trusted_root, args.state, args.output, args.target, args.force)
    except KeyboardInterrupt:
        parser.exit(130, "Verification interrupted; embedded checker rules retained.\n")
    except ImportError:
        parser.exit(2, 'Optional TUF dependencies missing; see tools/signed_rules/README.md\n')
    except Exception:
        parser.exit(2, 'Bundle verification failed; existing output and embedded checker rules retained.\n')
    print('Verified target sha256:' + digest + '; publisher authentication does not validate advisory claims.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
