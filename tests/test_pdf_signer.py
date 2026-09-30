"""
Unit test for PDF PAdES signing engine.
"""

import os
import tempfile
import unittest
from core.cert_manager import CertManager
from core.signer import TokenSigner


class TestPdfSigner(unittest.TestCase):

    def test_pdf_signing(self):
        # Create a minimal valid PDF 1.4 document
        minimal_pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Hello Indian DSC) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \n"
            b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n300\n%%EOF\n"
        )

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as in_f:
            in_f.write(minimal_pdf)
            in_path = in_f.name

        out_path = in_path + ".signed.pdf"

        cert = CertManager.generate_simulated_dsc(
            cn="TEST SIGNER",
            pan="AAAPZ1111A",
        )

        signer = TokenSigner()
        result = signer.sign_pdf(
            input_pdf_path=in_path,
            output_pdf_path=out_path,
            token_id="SIMULATED",
            slot=0,
            pin="12345678",
            cert=cert,
            reason="Income Tax Return Verification",
            location="Chennai",
            is_simulated=True,
        )

        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(out_path))

        with open(out_path, "rb") as f:
            signed_data = f.read()

        # Check signature dictionary elements in signed PDF
        self.assertIn(b"/Type /Sig", signed_data)
        self.assertIn(b"/Filter /Adobe.PPKLite", signed_data)
        self.assertIn(b"/SubFilter /adbe.pkcs7.detached", signed_data)
        self.assertIn(b"/ByteRange", signed_data)
        self.assertIn(b"TEST SIGNER", signed_data)
        self.assertIn(b"Income Tax Return Verification", signed_data)

        # Cleanup
        try:
            os.remove(in_path)
            os.remove(out_path)
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main()
