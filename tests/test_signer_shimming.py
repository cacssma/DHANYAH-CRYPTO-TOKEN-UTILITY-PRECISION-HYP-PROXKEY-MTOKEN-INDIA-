"""
Unit tests for FIPS L2/L3 SHA-1 Mechanism Shimming in TokenSigner.
"""

import hashlib
import unittest
from core.signer import TokenSigner
from core.cert_manager import CertManager


class TestSignerShimming(unittest.TestCase):

    def setUp(self):
        self.signer = TokenSigner()

    def test_sha1_hash_signing_simulated(self):
        # 20-byte SHA-1 hash of b"Test Document"
        sha1_digest = hashlib.sha1(b"Test Document").digest()
        self.assertEqual(len(sha1_digest), 20)

        sig = self.signer.sign_hash_hardware(
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            data_hash=sha1_digest,
            algo="SHA1",
            is_simulated=True,
        )
        self.assertIsInstance(sig, bytes)
        self.assertEqual(len(sig), 256)  # 2048-bit RSA signature = 256 bytes

    def test_sha256_hash_signing_simulated(self):
        # 32-byte SHA-256 hash of b"Test Document"
        sha256_digest = hashlib.sha256(b"Test Document").digest()
        self.assertEqual(len(sha256_digest), 32)

        sig = self.signer.sign_hash_hardware(
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            data_hash=sha256_digest,
            algo="SHA256",
            is_simulated=True,
        )
        self.assertIsInstance(sig, bytes)
        self.assertEqual(len(sig), 256)

    def test_sign_data_method(self):
        raw_data = b"Government Portal Income Tax Verification String 2026"
        sig_sha1 = self.signer.sign_data(
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            raw_data=raw_data,
            algo="SHA1",
            is_simulated=True,
        )
        self.assertEqual(len(sig_sha1), 256)

        sig_sha256 = self.signer.sign_data(
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            raw_data=raw_data,
            algo="SHA256",
            is_simulated=True,
        )
        self.assertEqual(len(sig_sha256), 256)


if __name__ == "__main__":
    unittest.main()
