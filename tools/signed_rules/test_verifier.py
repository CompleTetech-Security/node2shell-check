"""Synthetic signing keys only; no network, production key, or live rules."""
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import Metadata, Root, Targets, Timestamp, Snapshot, TargetFile, MetaFile

spec = importlib.util.spec_from_file_location('verify_bundle', Path(__file__).with_name('verify_bundle.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bundle = self.directory / 'bundle'
        for name in ('metadata', 'targets'):
            (self.bundle / name).mkdir(parents=True)
        self.rootfile = self.directory / 'pinned-root.json'
        self.output = self.directory / 'verified.json'
        self.state = self.directory / 'state'
        self.expires = datetime.now(timezone.utc) + timedelta(days=5)
        self.keys = {role: CryptoSigner.generate_ed25519() for role in ('root','targets','snapshot','timestamp')}
        self.root = Metadata(Root(expires=self.expires))
        for role,key in self.keys.items():
            self.root.signed.add_key(key.public_key, role)
        self.root.sign(self.keys['root'])
        self.rootfile.write_bytes(self.root.to_bytes())
        self.data = b'{"schema_version":1,"synthetic":true}\n'
        self.publish()

    def publish(self, version=1, expired=False, data=None):
        data = self.data if data is None else data
        expiry = datetime.now(timezone.utc) - timedelta(days=1) if expired else self.expires
        targets = Metadata(Targets(version=version, expires=expiry))
        info = TargetFile.from_data('rules.json', data)
        targets.signed.targets['rules.json'] = info
        targets.sign(self.keys['targets'])
        target_bytes = targets.to_bytes()
        snapshot = Metadata(Snapshot(version=version, expires=expiry))
        snapshot.signed.meta['targets.json'] = MetaFile.from_data(version, target_bytes, ['sha256'])
        snapshot.sign(self.keys['snapshot'])
        snapshot_bytes = snapshot.to_bytes()
        timestamp = Metadata(Timestamp(version=version, expires=expiry))
        timestamp.signed.snapshot_meta = MetaFile.from_data(version, snapshot_bytes, ['sha256'])
        timestamp.sign(self.keys['timestamp'])
        for name,content in [('timestamp.json',timestamp.to_bytes()),(f'{version}.snapshot.json',snapshot_bytes),(f'{version}.targets.json',target_bytes)]:
            (self.bundle/'metadata'/name).write_bytes(content)
        for digest in info.hashes.values():
            (self.bundle/'targets'/(digest+'.rules.json')).write_bytes(data)

    def verify(self, **kwargs):
        with patch('socket.socket', side_effect=AssertionError('network forbidden')):
            return v.verify(self.bundle,self.rootfile,self.state,self.output,'rules.json',**kwargs)

    def test_verified_target_no_execution_no_network_and_no_clobber(self):
        self.assertEqual(hashlib.sha256(self.data).hexdigest(), self.verify())
        self.assertEqual(self.data, self.output.read_bytes())
        with self.assertRaises(ValueError): self.verify()
        self.verify(force=True)
        self.assertFalse((self.state/'update.lock').exists())

    def test_tampered_target_retains_previous_output(self):
        self.verify()
        self.publish(2, data=b'{"new":true}')
        for path in (self.bundle/'targets').iterdir(): path.write_bytes(b'broken')
        with self.assertRaises(Exception): self.verify(force=True)
        self.assertEqual(self.data,self.output.read_bytes())
        self.assertFalse((self.state/'update.lock').exists())

    def test_wrong_signer_and_unsigned_metadata_rejected(self):
        for unsigned in (False,True):
            self.publish()
            path=self.bundle/'metadata'/'timestamp.json'
            md=Metadata.from_bytes(path.read_bytes())
            md.signatures.clear()
            if not unsigned: md.sign(CryptoSigner.generate_ed25519())
            path.write_bytes(md.to_bytes())
            with self.assertRaises(Exception): self.verify()
            self.assertFalse(self.output.exists())

    def test_expired_and_rollback_rejected(self):
        self.publish(expired=True)
        with self.assertRaises(Exception): self.verify()
        self.publish(2)
        self.verify()
        self.publish(1)
        with self.assertRaises(Exception): self.verify(force=True)
        self.assertEqual(self.data,self.output.read_bytes())

    def test_dual_signed_root_rotation_and_revoked_release_key(self):
        self.verify()
        oldroot=self.keys['root']
        oldtargets=self.keys['targets']
        self.keys['root']=CryptoSigner.generate_ed25519()
        self.keys['targets']=CryptoSigner.generate_ed25519()
        rotated=Metadata(Root(version=2,expires=self.expires))
        for role,key in self.keys.items(): rotated.signed.add_key(key.public_key,role)
        rotated.sign(oldroot)
        rotated.sign(self.keys['root'],append=True)
        (self.bundle/'metadata'/'2.root.json').write_bytes(rotated.to_bytes())
        self.publish(2)
        self.verify(force=True)
        self.assertEqual(2,Metadata.from_bytes((self.state/'metadata'/'root.json').read_bytes()).signed.version)
        path=self.bundle/'metadata'/'2.targets.json'
        # Root rotation must not permit an untrusted targets signing key.
        md=Metadata.from_bytes(path.read_bytes())
        md.signatures.clear(); md.sign(CryptoSigner.generate_ed25519())
        path.write_bytes(md.to_bytes())
        # Re-sign the envelope descriptors so this exercises signature trust, not only hashes.
        self.publish(3)
        path=self.bundle/'metadata'/'3.targets.json'
        md=Metadata.from_bytes(path.read_bytes()); md.signatures.clear(); md.sign(oldtargets)
        raw=md.to_bytes();path.write_bytes(raw)
        snap=Metadata.from_bytes((self.bundle/'metadata'/'3.snapshot.json').read_bytes())
        snap.signed.meta['targets.json']=MetaFile.from_data(3,raw,['sha256']);snap.sign(self.keys['snapshot'])
        raw=snap.to_bytes();(self.bundle/'metadata'/'3.snapshot.json').write_bytes(raw)
        stamp=Metadata.from_bytes((self.bundle/'metadata'/'timestamp.json').read_bytes())
        stamp.signed.snapshot_meta=MetaFile.from_data(3,raw,['sha256']);stamp.sign(self.keys['timestamp'])
        (self.bundle/'metadata'/'timestamp.json').write_bytes(stamp.to_bytes())
        with self.assertRaises(Exception): self.verify(force=True)

    def test_untrusted_root_rotation_and_changed_bootstrap_rejected(self):
        self.verify()
        md=Metadata(Root(version=2,expires=self.expires))
        for role,key in self.keys.items(): md.signed.add_key(key.public_key,role)
        md.sign(CryptoSigner.generate_ed25519())
        (self.bundle/'metadata'/'2.root.json').write_bytes(md.to_bytes())
        with self.assertRaises(Exception): self.verify(force=True)
        self.rootfile.write_bytes(self.rootfile.read_bytes()+b' ')
        with self.assertRaises(ValueError): self.verify(force=True)

    def test_two_of_three_root_threshold_requires_two_signatures(self):
        extra = [CryptoSigner.generate_ed25519(), CryptoSigner.generate_ed25519()]
        for signer in extra:
            self.root.signed.add_key(signer.public_key, "root")
        self.root.signed.roles["root"].threshold = 2
        self.root.sign(self.keys["root"])
        self.root.sign(extra[0], append=True)
        self.rootfile.write_bytes(self.root.to_bytes())
        self.verify()
        rotated = Metadata.from_bytes(self.root.to_bytes())
        rotated.signed.version = 2
        rotated.sign(self.keys["root"])
        (self.bundle/"metadata"/"2.root.json").write_bytes(rotated.to_bytes())
        with self.assertRaises(Exception): self.verify(force=True)
        rotated.sign(extra[1], append=True)
        (self.bundle/"metadata"/"2.root.json").write_bytes(rotated.to_bytes())
        self.verify(force=True)

    def test_cached_history_does_not_consume_new_rotation_budget(self):
        def roots(first, last):
            for version in range(first,last+1):
                md=Metadata.from_bytes(self.root.to_bytes())
                md.signed.version=version
                md.sign(self.keys["root"])
                (self.bundle/"metadata"/(str(version)+".root.json")).write_bytes(md.to_bytes())
        roots(2,20)
        self.verify()
        roots(21,40)
        self.verify(force=True)
        md=Metadata.from_bytes((self.state/"metadata"/"root.json").read_bytes())
        self.assertEqual(40,md.signed.version)

    def test_stale_snapshot_and_malformed_json_retain_verified_output(self):
        self.publish(2)
        self.verify()
        self.publish(1)
        # A newer timestamp advertising an older snapshot must still fail.
        path=self.bundle/"metadata"/"timestamp.json"
        md=Metadata.from_bytes(path.read_bytes());md.signed.version=3;md.sign(self.keys["timestamp"])
        path.write_bytes(md.to_bytes())
        with self.assertRaises(Exception): self.verify(force=True)
        self.publish(4,data=b"not JSON")
        with self.assertRaises(ValueError): self.verify(force=True)
        self.assertEqual(self.data,self.output.read_bytes())

    def test_lock_and_protected_outputs(self):
        self.state.mkdir(); lock=self.state/'update.lock';lock.write_text('other owner')
        with self.assertRaises(FileExistsError): self.verify()
        self.assertEqual('other owner',lock.read_text())
        lock.unlink()
        for output in (self.rootfile,self.bundle/'new.json',self.state/'active.json'):
            with self.assertRaises(ValueError): v.verify(self.bundle,self.rootfile,self.state,output,'rules.json',True)
        for target in ('../rules.json','https://example.invalid/rules.json','/rules.json'):
            with self.assertRaises(ValueError): v.verify(self.bundle,self.rootfile,self.state,self.output,target)


if __name__ == '__main__': unittest.main()
