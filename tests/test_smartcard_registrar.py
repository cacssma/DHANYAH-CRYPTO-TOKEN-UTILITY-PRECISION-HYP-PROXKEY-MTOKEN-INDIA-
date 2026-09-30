"""
Unit tests for Windows Smart Card & MiniDriver Registrar.
"""

import unittest
from core.smartcard_registrar import SmartCardRegistrar, CARD_DEFINITIONS


class TestSmartCardRegistrar(unittest.TestCase):

    def test_definitions_completeness(self):
        for expected in ["hyp2003", "hyp2003_v33", "mtoken_blue", "mtoken_purple", "proxkey", "innait"]:
            self.assertIn(expected, CARD_DEFINITIONS)
            cfg = CARD_DEFINITIONS[expected]
            self.assertIn("name", cfg)
            self.assertIn("atr", cfg)
            self.assertIn("atr_mask", cfg)
            self.assertIn("crypto_provider", cfg)
            self.assertTrue(len(cfg["atr"]) > 0)
            self.assertTrue(len(cfg["atr_mask"]) > 0)

    def test_health_check(self):
        health = SmartCardRegistrar.check_subsystem_health()
        self.assertIn("cards", health)
        self.assertIn("services", health)
        self.assertIn("is_admin", health)
        self.assertIn("mtoken_blue", health["cards"])
        self.assertIn("mtoken_purple", health["cards"])
        self.assertIn("hyp2003_v33", health["cards"])
        self.assertIn("proxkey", health["cards"])
        self.assertIn("innait", health["cards"])

    def test_pulse_does_not_crash(self):
        # Pulsing certificates should return boolean
        res = SmartCardRegistrar.pulse_windows_certificates()
        self.assertIsInstance(res, bool)


if __name__ == "__main__":
    unittest.main()
