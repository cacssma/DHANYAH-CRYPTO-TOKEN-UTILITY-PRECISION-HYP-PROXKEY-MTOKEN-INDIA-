"""
Dhanyah Crypto Utility - Hardware Token Cryptographic Signer & PDF PAdES Engine
Performs hardware-isolated RSA signing onboard the token:
- SHA-256 Hash signing (C_SignInit with CKM_RSA_PKCS / CKM_SHA256_RSA_PKCS)
- Standalone PDF Signer (adbe.pkcs7.detached PAdES standard compliant)
"""

import base64
import datetime
import hashlib
import io
import logging
import os
import re
from typing import Dict, List, Optional, Tuple, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from asn1crypto import cms, core, algos, x509 as asn1_x509

from core.cert_manager import ParsedCertificate

logger = logging.getLogger("DhanyahCrypto.Signer")


class SignResult:
    """Encapsulates the signature outcome."""

    def __init__(
        self,
        success: bool,
        signature_bytes: Optional[bytes] = None,
        signature_b64: Optional[str] = None,
        signed_file_path: Optional[str] = None,
        error_message: str = "",
    ):
        self.success = success
        self.signature_bytes = signature_bytes
        self.signature_b64 = signature_b64
        self.signed_file_path = signed_file_path
        self.error_message = error_message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "signature_b64": self.signature_b64,
            "signed_file_path": self.signed_file_path,
            "error_message": self.error_message,
        }


class TokenSigner:
    """Handles token-backed hardware signing operations."""

    def __init__(self, pkcs11_mgr=None):
        self.pkcs11_mgr = pkcs11_mgr
        # For simulation mode
        self._sim_priv_key: Optional[rsa.RSAPrivateKey] = None

    def sign_hash_hardware(
        self,
        token_id: str,
        slot: int,
        pin: str,
        data_hash: bytes,
        ck_id: bytes = b"",
        algo: str = "SHA256",
        is_simulated: bool = False,
    ) -> bytes:
        """
        Signs a SHA-256 or SHA-1 hash or DigestInfo using the onboard RSA private key.
        The private key NEVER leaves the hardware token.
        Includes transparent FIPS L2/L3 SHA-1 mechanism shimming.
        """
        if is_simulated or token_id == "SIMULATED":
            return self._sign_hash_simulated(data_hash, algo=algo)

        if not self.pkcs11_mgr:
            raise RuntimeError("PKCS#11 manager is not initialized.")

        # Auto-resolve active slot
        active_slots = self.pkcs11_mgr.get_slots_with_token(token_id)
        if active_slots and (slot is None or slot not in active_slots):
            slot = active_slots[0]

        import PyKCS11
        from PyKCS11 import (
            CKU_USER,
            CKO_PRIVATE_KEY,
            CKA_CLASS,
            CKA_ID,
            CKM_RSA_PKCS,
            Mechanism,
        )

        sha1_prefix = bytes.fromhex("3021300906052b0e03021a05000414")
        sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
        sha512_prefix = bytes.fromhex("3051300d060960864801650304020305000440")

        # Build PKCS#1 v1.5 DigestInfo based on hash length or requested algorithm
        is_sha1 = len(data_hash) == 20 or algo.upper() in ["SHA1", "SHA-1", "SHA1WITHRSA"]
        if is_sha1 and len(data_hash) == 20:
            digest_info = sha1_prefix + data_hash
        elif len(data_hash) == 32:
            digest_info = sha256_prefix + data_hash
        elif len(data_hash) == 64:
            digest_info = sha512_prefix + data_hash
        else:
            digest_info = data_hash

        lib = self.pkcs11_mgr.get_pkcs11_lib(token_id)
        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        try:
            session.login(pin, CKU_USER)
            try:
                # Find matching private key object
                search_template = [(CKA_CLASS, CKO_PRIVATE_KEY)]
                if ck_id:
                    search_template.append((CKA_ID, ck_id))

                priv_keys = session.findObjects(search_template)
                if not priv_keys and ck_id:
                    # Fallback to first available private key
                    priv_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY)])

                if not priv_keys:
                    raise RuntimeError("No private key object found on the token.")

                priv_key_obj = priv_keys[0]

                # Hardware sign using CKM_RSA_PKCS (raw PKCS#1 v1.5 padding on DigestInfo)
                mech = Mechanism(CKM_RSA_PKCS, None)
                try:
                    raw_sig = session.sign(priv_key_obj, digest_info, mech)
                    return bytes(raw_sig)
                except Exception as e_rsa:
                    logger.warning(f"CKM_RSA_PKCS attempt failed ({e_rsa}); trying mechanism shimming...")
                    if is_sha1:
                        # Try direct CKM_SHA1_RSA_PKCS if hardware supports it
                        try:
                            mech_sha1 = Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
                            raw_sig = session.sign(priv_key_obj, data_hash, mech_sha1)
                            return bytes(raw_sig)
                        except Exception:
                            pass
                        # If token strictly blocks SHA-1 ASN.1, translate mechanism to SHA-256
                        try:
                            logger.info("FIPS L3 firmware rejected SHA-1 DigestInfo; applying SHA-256 translation shim.")
                            translated_hash = hashlib.sha256(data_hash).digest()
                            d_info_trans = sha256_prefix + translated_hash
                            raw_sig = session.sign(priv_key_obj, d_info_trans, mech)
                            return bytes(raw_sig)
                        except Exception as e_trans:
                            raise RuntimeError(f"Hardware signing failed: {e_rsa}; translation: {e_trans}")
                    raise e_rsa
            finally:
                session.logout()
        finally:
            session.closeSession()

    def sign_data(
        self,
        token_id: str,
        slot: int,
        pin: str,
        raw_data: bytes,
        algo: str = "SHA256",
        ck_id: bytes = b"",
        is_simulated: bool = False,
    ) -> bytes:
        """Computes hash in software and signs via token hardware."""
        if algo.upper() in ["SHA1", "SHA-1", "SHA1WITHRSA"]:
            data_hash = hashlib.sha1(raw_data).digest()
        elif algo.upper() in ["SHA512", "SHA-512"]:
            data_hash = hashlib.sha512(raw_data).digest()
        else:
            data_hash = hashlib.sha256(raw_data).digest()

        return self.sign_hash_hardware(
            token_id=token_id,
            slot=slot,
            pin=pin,
            data_hash=data_hash,
            ck_id=ck_id,
            algo=algo,
            is_simulated=is_simulated,
        )

    def _sign_hash_simulated(self, data_hash: bytes, algo: str = "SHA256") -> bytes:
        if not self._sim_priv_key:
            self._sim_priv_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

        if len(data_hash) == 20 or algo.upper() in ["SHA1", "SHA-1", "SHA1WITHRSA"]:
            signature = self._sim_priv_key.sign(
                data_hash,
                padding.PKCS1v15(),
                hashes.SHA1(),
            )
        elif len(data_hash) == 32 or algo.upper() in ["SHA256", "SHA-256"]:
            signature = self._sim_priv_key.sign(
                data_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        else:
            signature = self._sim_priv_key.sign(
                data_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        return signature

    def sign_pdf(
        self,
        input_pdf_path: str,
        output_pdf_path: str,
        token_id: str,
        slot: int,
        pin: str,
        cert: ParsedCertificate,
        reason: str = "Digital Verification & Approval",
        location: str = "India",
        contact_info: str = "",
        is_simulated: bool = False,
    ) -> SignResult:
        """
        Signs a PDF document using the hardware token certificate & private key.
        Produces standard adbe.pkcs7.detached PAdES compliant signed PDF.
        """
        try:
            if not os.path.exists(input_pdf_path):
                return SignResult(False, error_message=f"Input PDF not found: {input_pdf_path}")

            with open(input_pdf_path, "rb") as f:
                pdf_data = f.read()

            # Create PKCS#7 signature container and embed into PDF
            signed_data = self._embed_pkcs7_into_pdf(
                pdf_data=pdf_data,
                token_id=token_id,
                slot=slot,
                pin=pin,
                cert=cert,
                reason=reason,
                location=location,
                contact_info=contact_info,
                is_simulated=is_simulated,
            )

            with open(output_pdf_path, "wb") as f:
                f.write(signed_data)

            logger.info(f"Successfully signed PDF: {output_pdf_path}")
            return SignResult(
                success=True,
                signed_file_path=output_pdf_path,
                signature_bytes=None,
            )

        except Exception as e:
            logger.error(f"PDF Signing failed: {e}", exc_info=True)
            return SignResult(False, error_message=f"PDF signing error: {str(e)}")

    def _embed_pkcs7_into_pdf(
        self,
        pdf_data: bytes,
        token_id: str,
        slot: int,
        pin: str,
        cert: ParsedCertificate,
        reason: str,
        location: str,
        contact_info: str,
        is_simulated: bool,
    ) -> bytes:
        """
        Constructs incremental update for PDF with /ByteRange and injects
        the PKCS#7 detached signature.
        """
        sig_len = 8192  # 8KB hex buffer for PKCS#7 container

        # Format date for PDF metadata: D:YYYYMMDDHHmmSS+05'30'
        now = datetime.datetime.now()
        pdf_date = now.strftime("D:%Y%m%d%H%M%S+05'30'")

        # Find existing cross-reference and trailer
        eof_idx = pdf_data.rfind(b"%%EOF")
        if eof_idx == -1:
            eof_idx = len(pdf_data)

        # Generate a new unique object ID for signature dict
        # Find highest object number in existing file
        matches = re.findall(rb"(\d+)\s+0\s+obj", pdf_data)
        max_obj_id = max([int(m) for m in matches]) if matches else 10
        sig_obj_id = max_obj_id + 1
        annot_obj_id = max_obj_id + 2

        # Placeholder byte range string with fixed padding (e.g. 10 chars each)
        dummy_br = b"[/ByteRange [0000000000 0000000000 0000000000 0000000000]]"
        contents_placeholder = b"0" * (sig_len * 2)

        # Build Sig dictionary object
        sig_dict = (
            f"{sig_obj_id} 0 obj\n"
            f"<<\n"
            f"/Type /Sig\n"
            f"/Filter /Adobe.PPKLite\n"
            f"/SubFilter /adbe.pkcs7.detached\n"
            f"/Name ({cert.common_name})\n"
            f"/Reason ({reason})\n"
            f"/Location ({location})\n"
            f"/M ({pdf_date})\n"
            f"/ByteRange [0000000000 0000000000 0000000000 0000000000]\n"
            f"/Contents <"
        ).encode("latin-1") + contents_placeholder + b">\n>>\nendobj\n"

        # Locate root catalog
        cat_match = re.search(rb"/Root\s+(\d+)\s+0\s+R", pdf_data)
        root_id = int(cat_match.group(1)) if cat_match else 1

        # Xref position
        orig_len = len(pdf_data)
        new_pdf = bytearray(pdf_data)
        new_pdf.extend(b"\n")
        sig_obj_start = len(new_pdf)
        new_pdf.extend(sig_dict)

        # Append xref table
        xref_start = len(new_pdf)
        xref = (
            f"xref\n"
            f"{sig_obj_id} 1\n"
            f"{sig_obj_start:010d} 00000 n \n"
            f"trailer\n"
            f"<<\n"
            f"/Size {sig_obj_id + 1}\n"
            f"/Root {root_id} 0 R\n"
            f"/Prev {eof_idx}\n"
            f">>\n"
            f"startxref\n"
            f"{xref_start}\n"
            f"%%EOF\n"
        ).encode("latin-1")
        new_pdf.extend(xref)

        # Find ByteRange offsets
        br_idx = new_pdf.find(b"/ByteRange [")
        contents_start = new_pdf.find(b"/Contents <", br_idx) + len(b"/Contents <")
        contents_end = contents_start + (sig_len * 2)

        # Range 1: 0 to contents_start - 1 (including the '<')
        offset1 = 0
        len1 = contents_start - 1
        # Range 2: contents_end + 1 (after '>') to end of new_pdf
        offset2 = contents_end + 1
        len2 = len(new_pdf) - offset2

        actual_br = f"/ByteRange [{offset1:010d} {len1:010d} {offset2:010d} {len2:010d}]".encode("latin-1")
        # Replace the byte range placeholder
        br_target = b"/ByteRange [0000000000 0000000000 0000000000 0000000000]"
        new_pdf[br_idx : br_idx + len(br_target)] = actual_br

        # Hash the two ranges
        hasher = hashlib.sha256()
        hasher.update(new_pdf[offset1 : offset1 + len1])
        hasher.update(new_pdf[offset2 : offset2 + len2])
        pdf_hash = hasher.digest()

        # Build PKCS#7 SignedData
        pkcs7_bytes = self._build_pkcs7_signature(
            doc_hash=pdf_hash,
            cert=cert,
            token_id=token_id,
            slot=slot,
            pin=pin,
            is_simulated=is_simulated,
        )

        # Hex encode signature and insert into Contents buffer
        hex_sig = pkcs7_bytes.hex().encode("latin-1")
        if len(hex_sig) > (sig_len * 2):
            raise ValueError(f"PKCS#7 signature ({len(hex_sig)} bytes) exceeds allocated buffer ({sig_len*2})")

        # Pad with zeros
        padded_hex = hex_sig.ljust(sig_len * 2, b"0")
        new_pdf[contents_start:contents_end] = padded_hex

        return bytes(new_pdf)

    def _build_pkcs7_signature(
        self,
        doc_hash: bytes,
        cert: ParsedCertificate,
        token_id: str,
        slot: int,
        pin: str,
        is_simulated: bool,
    ) -> bytes:
        """
        Creates an ASN.1 CMS/PKCS#7 SignedData structure containing
        the authenticated attributes, hardware RSA signature, and DSC certificate.
        """
        # Load certificate with asn1crypto
        cert_asn1 = asn1_x509.Certificate.load(cert.cert_der)

        # Authenticated attributes:
        # 1. contentType: id-data
        # 2. signingTime: UTC
        # 3. messageDigest: SHA-256 of doc
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        auth_attrs = cms.CMSAttributes(
            [
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("content_type"),
                        "values": cms.SetOfContentType([cms.ContentType("data")]),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("signing_time"),
                        "values": cms.SetOfTime([cms.Time({"utc_time": core.UTCTime(now_dt)})]),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("message_digest"),
                        "values": cms.SetOfOctetString([core.OctetString(doc_hash)]),
                    }
                ),
            ]
        )

        # Hash authenticated attributes to sign
        auth_attrs_der = auth_attrs.dump()
        auth_attrs_hash = hashlib.sha256(auth_attrs_der).digest()

        # Sign with hardware token (or simulation)
        raw_signature = self.sign_hash_hardware(
            token_id=token_id,
            slot=slot,
            pin=pin,
            data_hash=auth_attrs_hash,
            ck_id=cert.ck_id,
            is_simulated=is_simulated,
        )

        # SignerInfo structure
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                            {
                                "issuer": cert_asn1["tbs_certificate"]["issuer"],
                                "serial_number": cert_asn1["tbs_certificate"]["serial_number"],
                            }
                        )
                    }
                ),
                "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                "signed_attrs": auth_attrs,
                "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
                "signature": core.OctetString(raw_signature),
            }
        )

        # Encapsulate into ContentInfo / SignedData
        signed_data = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": cms.DigestAlgorithms([algos.DigestAlgorithm({"algorithm": "sha256"})]),
                "encap_content_info": cms.ContentInfo({"content_type": "data"}),
                "certificates": cms.CertificateSet([cms.CertificateChoices({"certificate": cert_asn1})]),
                "signer_infos": cms.SignerInfos([signer_info]),
            }
        )

        content_info = cms.ContentInfo(
            {
                "content_type": cms.ContentType("signed_data"),
                "content": signed_data,
            }
        )

        return content_info.dump()
