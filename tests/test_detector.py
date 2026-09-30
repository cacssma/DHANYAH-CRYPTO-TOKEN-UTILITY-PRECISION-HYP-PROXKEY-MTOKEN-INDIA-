"""
Unit tests for Token Detector, ATR recognition, and hotplug management.
"""

import unittest
from core.constants import (
    TOKEN_HYP2003,
    TOKEN_MTOKEN,
    TOKEN_PROXKEY,
    TOKEN_INNAIT,
)
from core.token_detector import (
    identify_token_by_atr,
    identify_token_by_reader_name,
    TokenDetector,
)


class TestTokenDetector(unittest.TestCase):

    def test_hyp2003_atr_recognition(self):
        atr = "3B 9F 95 81 31 FE 9F 00 65 46 53 05 30 06 71 DF 00 00 00 80"
        profile = identify_token_by_atr(atr)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["id"], TOKEN_HYP2003)
        self.assertIn("HyperPKI", profile["name"])

    def test_mtoken_atr_recognition(self):
        atr = "3B 7D 94 00 00 57 44 53 00 00 00 00 00 00 00 00 00 00"
        profile = identify_token_by_atr(atr)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["id"], TOKEN_MTOKEN)
        self.assertIn("mToken", profile["name"])

    def test_proxkey_atr_recognition(self):
        atr = "3B 6E 00 00 80 31 80 66 B0 84 12 01 6E 01 83 00 90 00"
        profile = identify_token_by_atr(atr)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["id"], TOKEN_PROXKEY)
        self.assertIn("Watchdata", profile["vendor"])

    def test_innait_atr_recognition(self):
        atr = "3B 88 80 01 20 00 00 00 01 00 00 00"
        profile = identify_token_by_atr(atr)
        self.assertIsNotNone(profile)
        self.assertEqual(profile["id"], TOKEN_INNAIT)
        self.assertIn("Precision", profile["name"])

    def test_reader_name_heuristics(self):
        self.assertEqual(identify_token_by_reader_name("Feitian Technologies ePass2003 0")["id"], TOKEN_HYP2003)
        self.assertEqual(identify_token_by_reader_name("Longmai mToken CryptoID Reader 0")["id"], TOKEN_MTOKEN)
        self.assertEqual(identify_token_by_reader_name("Watchdata PROXKey USB Reader 0")["id"], TOKEN_PROXKEY)
        self.assertEqual(identify_token_by_reader_name("Precision InnaITKey DSC 0")["id"], TOKEN_INNAIT)

    def test_simulation_mode(self):
        detector = TokenDetector()
        self.assertIsNone(detector.get_primary_token())

        detector.set_simulation_mode(TOKEN_HYP2003)
        token = detector.get_primary_token()
        self.assertIsNotNone(token)
        self.assertEqual(token.token_id, TOKEN_HYP2003)
        self.assertTrue(token.is_simulated)

        # Clear simulation
        detector.set_simulation_mode(None)
        self.assertIsNone(detector.get_primary_token())


if __name__ == "__main__":
    unittest.main()
