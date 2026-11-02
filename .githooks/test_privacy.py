"""匿名 Git 钩子的上游署名边界；只在海外 worker 运行。"""
import hashlib
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest


class UpstreamNoticeTests(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader('privacy', str(Path(__file__).with_name('privacy-check')))
        specification = importlib.util.spec_from_loader(loader.name, loader)
        self.privacy = importlib.util.module_from_spec(specification)
        loader.exec_module(self.privacy)

    def test_only_reviewed_notice_bytes_are_accepted(self):
        root = Path(__file__).resolve().parents[1]
        for name, digest in self.privacy.UPSTREAM_NOTICES.items():
            data = (root / name.decode()).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.privacy.git = lambda *_, value=data: value
            self.privacy.check_entry(b'100644', digest.encode(), name)
            self.privacy.CHECKED_BLOBS.clear()
            self.privacy.git = lambda *_: data + b'\n'
            with self.assertRaisesRegex(self.privacy.Rejected, 'upstream-notice-changed-needs-review'):
                self.privacy.check_entry(b'100644', digest.encode(), name)

    def test_first_party_paths_still_reject_identity_and_private_material(self):
        for data in [b'example@' + b'example.invalid', b'-----BEGIN PRIVATE' + b' KEY-----']:
            self.privacy.git = lambda *_, value=data: value
            with self.assertRaises(self.privacy.Rejected):
                self.privacy.check_entry(b'100644', b'0' * 40, b'crates/core-api/src/example.rs')

    def test_reviewed_blob_does_not_exempt_a_first_party_copy(self):
        root = Path(__file__).resolve().parents[1]
        name = b'third_party/shaped-rustls/LICENSE-MIT'
        data = (root / name.decode()).read_bytes()
        self.privacy.git = lambda *_: data
        oid = b'1' * 40
        self.privacy.check_entry(b'100644', oid, name)
        with self.assertRaisesRegex(self.privacy.Rejected, 'non-anonymous-email'):
            self.privacy.check_entry(b'100644', oid, b'crates/core-api/src/copied.rs')


if __name__ == '__main__':
    unittest.main()
