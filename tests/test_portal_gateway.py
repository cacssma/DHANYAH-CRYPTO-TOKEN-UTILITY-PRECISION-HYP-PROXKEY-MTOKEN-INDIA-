"""
Unit tests for Government Portal Gateway (emBridge and emSigner protocols).
"""

import base64
import json
import time
import unittest
import urllib.request
from core.token_detector import TokenDetector
from core.pkcs11_manager import PKCS11Manager
from core.cert_manager import CertManager
from core.pin_manager import PinManager
from core.signer import TokenSigner
from core.constants import TOKEN_HYP2003
from server.loopback_server import LoopbackServer


class TestPortalGateway(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.detector = TokenDetector()
        cls.pkcs11_mgr = PKCS11Manager()
        cls.cert_mgr = CertManager(cls.pkcs11_mgr)
        cls.pin_mgr = PinManager(cls.pkcs11_mgr)
        cls.signer = TokenSigner(cls.pkcs11_mgr)

        cls.port = 18206
        cls.server = LoopbackServer(
            token_detector=cls.detector,
            pkcs11_mgr=cls.pkcs11_mgr,
            cert_manager=cls.cert_mgr,
            pin_manager=cls.pin_mgr,
            signer=cls.signer,
            port=cls.port,
        )
        cls.server.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_embridge_version(self):
        url = f"http://127.0.0.1:{self.port}/DSC/Version"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], 1)
            self.assertIn("version", data)

    def test_embridge_list_token_and_certs(self):
        # Enable simulation token
        self.detector.set_simulation_mode(TOKEN_HYP2003)

        # 1. ListToken
        url_tokens = f"http://127.0.0.1:{self.port}/DSC/ListToken"
        req = urllib.request.Request(url_tokens, data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], 1)
            self.assertTrue(len(data["tokenList"]) > 0)
            self.assertIn("HYP 2003", data["tokenList"][0]["tokenName"])

        # 2. ListCertificate
        url_certs = f"http://127.0.0.1:{self.port}/DSC/ListCertificate"
        req_c = urllib.request.Request(url_certs, data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_c, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data_c = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data_c["status"], 1)
            self.assertTrue(len(data_c["certificateList"]) > 0)
            self.assertIn("RAMESH SHARMA", data_c["certificateList"][0]["commonName"])

        # 3. PKCSSign (emBridge signing)
        url_sign = f"http://127.0.0.1:{self.port}/DSC/PKCSSign"
        payload = json.dumps({
            "pin": "12345678",
            "data": base64.b64encode(b"IncomeTax Return Form 2026").decode("ascii"),
            "algo": "SHA256",
        }).encode("utf-8")
        req_s = urllib.request.Request(url_sign, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req_s, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data_s = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data_s["status"], 1)
            self.assertIn("signature", data_s)
            self.assertTrue(len(data_s["signature"]) > 0)

        # 4. emSigner getCertificate (GST portal)
        url_emsigner = f"http://127.0.0.1:{self.port}/getCertificate"
        req_em = urllib.request.Request(url_emsigner)
        with urllib.request.urlopen(req_em, timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            data_em = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data_em["status"], "success")
            self.assertTrue(len(data_em["certificates"]) > 0)

        # Clear simulation
        self.detector.set_simulation_mode(None)


if __name__ == "__main__":
    unittest.main()
