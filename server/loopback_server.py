"""
Dhanyah Crypto Utility - Local Loopback Gateway Server (Port 18200)
Provides REST & JSON endpoints with CORS support for:
- Web portals (MCA, GST, EPFO, Income Tax, Tenders)
- Accounting tools (Tally, SAP, ERPs)
- Browser DSC signer extensions
"""

import base64
import json
import logging
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Any

from core.constants import DEFAULT_LOOPBACK_HOST, DEFAULT_LOOPBACK_PORT

logger = logging.getLogger("DhanyahCrypto.Loopback")


class LoopbackRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests with full CORS headers and JSON responses."""

    server_app = None  # Reference to parent LoopbackServer

    def _set_cors_headers(self, status_code: int = 200, content_type: str = "application/json"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.end_headers()

    def do_OPTIONS(self):
        """Handle preflight CORS requests."""
        self._set_cors_headers(200)

    def do_GET(self):
        """Handle GET requests."""
        self._log_request()
        path = self.path.split("?")[0]

        # emBridge Endpoints (Income Tax / MCA V3)
        if path == "/DSC/Version":
            self._handle_embridge_version()
        elif path == "/DSC/ListToken":
            self._handle_embridge_list_token()
        elif path == "/DSC/ListCertificate":
            self._handle_embridge_list_certificate()
        # emSigner Endpoints (GST Portal / Traces)
        elif path in ["/getCertificate", "/getCertificates"]:
            self._handle_emsigner_certificates()
        # Dhanyah Native Endpoints
        elif path in ["/", "/status", "/health"]:
            self._handle_status()
        elif path in ["/certificates", "/certs"]:
            self._handle_certificates()
        elif path == "/drivers":
            self._handle_drivers()
        else:
            self._send_json(404, {"error": "Endpoint not found", "path": path})

    def do_POST(self):
        """Handle POST requests."""
        self._log_request()
        path = self.path.split("?")[0]

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 50 * 1024 * 1024:  # 50MB limit
            self._send_json(413, {"error": "Payload too large"})
            return

        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        # emBridge Endpoints
        if path == "/DSC/Version":
            self._handle_embridge_version()
        elif path == "/DSC/ListToken":
            self._handle_embridge_list_token()
        elif path == "/DSC/ListCertificate":
            self._handle_embridge_list_certificate()
        elif path == "/DSC/PKCSSign":
            self._handle_embridge_pkcs_sign(payload)
        elif path == "/DSC/Initialize":
            self._send_json(200, {"status": 1, "message": "Success"})
        # emSigner Endpoints
        elif path in ["/getCertificate", "/getCertificates"]:
            self._handle_emsigner_certificates()
        elif path in ["/sign", "/signData", "/getSign"]:
            self._handle_emsigner_sign(payload)
        # Dhanyah Native Endpoints
        elif path in ["/verify/pin", "/pin/verify"]:
            self._handle_verify_pin(payload)
        elif path in ["/sign/hash", "/hash/sign"]:
            self._handle_sign_hash(payload)
        elif path in ["/sign/pdf", "/pdf/sign"]:
            self._handle_sign_pdf(payload)
        elif path == "/":
            action = str(payload.get("action", "")).lower()
            if "cert" in action:
                self._handle_emsigner_certificates()
            elif "sign" in action:
                self._handle_emsigner_sign(payload)
            else:
                self._handle_status()
        else:
            self._send_json(404, {"error": "Endpoint not found", "path": path})

    def _handle_status(self):
        app = self.server_app
        token = app.get_primary_token()
        drivers = app.get_driver_statuses()

        data = {
            "status": "online",
            "service": "Dhanyah Crypto Utility Gateway",
            "port": app.port,
            "token_connected": token is not None,
            "token": token.to_dict() if token else None,
            "drivers": [d.to_dict() for d in drivers],
        }
        self._send_json(200, data)

    def _handle_drivers(self):
        app = self.server_app
        drivers = app.get_driver_statuses()
        self._send_json(200, {"drivers": [d.to_dict() for d in drivers]})

    def _handle_certificates(self):
        app = self.server_app
        certs = app.get_certificates()
        self._send_json(200, {"certificates": [c.to_dict() for c in certs]})

    def _handle_verify_pin(self, payload: Dict[str, Any]):
        app = self.server_app
        pin = payload.get("pin", "")
        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        res = app.pin_manager.verify_pin(
            token_id=token.token_id,
            slot=payload.get("slot", None),
            pin=pin,
            is_simulated=token.is_simulated,
        )
        self._send_json(200 if res.success else 401, res.to_dict())

    def _handle_sign_hash(self, payload: Dict[str, Any]):
        app = self.server_app
        pin = payload.get("pin", "")
        hash_hex = payload.get("hash_hex")
        hash_b64 = payload.get("hash_b64")

        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        if not pin:
            self._send_json(400, {"success": False, "error": "PIN is required."})
            return

        # Decode hash
        if hash_hex:
            try:
                data_hash = bytes.fromhex(hash_hex)
            except ValueError:
                self._send_json(400, {"success": False, "error": "Invalid hash_hex."})
                return
        elif hash_b64:
            try:
                data_hash = base64.b64decode(hash_b64)
            except Exception:
                self._send_json(400, {"success": False, "error": "Invalid hash_b64."})
                return
        else:
            self._send_json(400, {"success": False, "error": "hash_hex or hash_b64 is required."})
            return

        try:
            raw_sig = app.signer.sign_hash_hardware(
                token_id=token.token_id,
                slot=payload.get("slot", None),
                pin=pin,
                data_hash=data_hash,
                is_simulated=token.is_simulated,
            )
            self._send_json(
                200,
                {
                    "success": True,
                    "signature_hex": raw_sig.hex().upper(),
                    "signature_b64": base64.b64encode(raw_sig).decode("ascii"),
                },
            )
        except Exception as e:
            self._send_json(500, {"success": False, "error": str(e)})

    def _handle_sign_pdf(self, payload: Dict[str, Any]):
        app = self.server_app
        pdf_b64 = payload.get("pdf_base64", "")
        pin = payload.get("pin", "")
        reason = payload.get("reason", "Digitally Signed via Dhanyah Crypto Utility")
        location = payload.get("location", "India")

        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"success": False, "error": "No crypto token inserted."})
            return

        if not pdf_b64:
            self._send_json(400, {"success": False, "error": "pdf_base64 is required."})
            return

        certs = app.get_certificates()
        if not certs:
            self._send_json(400, {"success": False, "error": "No signing certificate available on token."})
            return

        cert = certs[0]

        try:
            pdf_bytes = base64.b64decode(pdf_b64)
            # Write temp input and output
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as in_f:
                in_f.write(pdf_bytes)
                in_path = in_f.name

            out_path = in_path + ".signed.pdf"

            res = app.signer.sign_pdf(
                input_pdf_path=in_path,
                output_pdf_path=out_path,
                token_id=token.token_id,
                slot=0,
                pin=pin,
                cert=cert,
                reason=reason,
                location=location,
                is_simulated=token.is_simulated,
            )

            if res.success and os.path.exists(out_path):
                with open(out_path, "rb") as out_f:
                    signed_pdf_bytes = out_f.read()

                # Clean up
                try:
                    os.remove(in_path)
                    os.remove(out_path)
                except Exception:
                    pass

                self._send_json(
                    200,
                    {
                        "success": True,
                        "signed_pdf_base64": base64.b64encode(signed_pdf_bytes).decode("ascii"),
                        "signer": cert.common_name,
                        "pan": cert.pan_number,
                    },
                )
            else:
                self._send_json(500, {"success": False, "error": res.error_message})

        except Exception as e:
            self._send_json(500, {"success": False, "error": str(e)})

    def _handle_embridge_version(self):
        self._send_json(
            200,
            {
                "status": 1,
                "version": "2.0.1",
                "message": "Success",
                "service": "Dhanyah Crypto Utility emBridge Bridge",
            },
        )

    def _handle_embridge_list_token(self):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(200, {"status": 0, "message": "No smart card or USB token detected.", "tokenList": []})
            return

        self._send_json(
            200,
            {
                "status": 1,
                "message": "Token list retrieved successfully",
                "tokenList": [
                    {
                        "tokenId": 0,
                        "tokenName": token.name,
                        "tokenSerial": token.serial_number or "DH-2026-FIPS3",
                        "status": "Connected",
                    }
                ],
            },
        )

    def _handle_embridge_list_certificate(self):
        app = self.server_app
        certs = app.get_certificates()
        if not certs:
            self._send_json(200, {"status": 0, "message": "No certificate found on token.", "certificateList": []})
            return

        cert_list = []
        for idx, cert in enumerate(certs):
            valid_from_str = cert.valid_from.strftime("%d-%m-%Y %H:%M:%S") if hasattr(cert, "valid_from") else ""
            valid_to_str = cert.valid_to.strftime("%d-%m-%Y %H:%M:%S") if hasattr(cert, "valid_to") else ""
            cert_b64 = base64.b64encode(cert.cert_der).decode("ascii")
            cert_list.append(
                {
                    "certId": idx,
                    "alias": cert.common_name,
                    "commonName": cert.common_name,
                    "issuer": cert.issuer_cn,
                    "serialNumber": cert.serial_number_hex,
                    "validFrom": valid_from_str,
                    "validTo": valid_to_str,
                    "certificate": cert_b64,
                    "publicKey": cert.fingerprint_sha256,
                    "pan": cert.pan_number or "",
                }
            )

        self._send_json(
            200,
            {
                "status": 1,
                "message": "Certificate list retrieved successfully",
                "certificateList": cert_list,
            },
        )

    def _handle_embridge_pkcs_sign(self, payload: Dict[str, Any]):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(200, {"status": 0, "message": "No token connected."})
            return

        raw_input = payload.get("data") or payload.get("hash") or payload.get("tbsData") or ""
        pin = payload.get("pin") or payload.get("password") or ""
        algo = payload.get("algo") or payload.get("algorithm") or "SHA256"

        if not raw_input:
            self._send_json(200, {"status": 0, "message": "No data or hash provided to sign."})
            return

        try:
            input_bytes = base64.b64decode(raw_input)
        except Exception:
            input_bytes = raw_input.encode("utf-8")

        certs = app.get_certificates()
        cert = certs[0] if certs else None
        ck_id = cert.ck_id if cert else b""

        try:
            if len(input_bytes) in [20, 32, 64]:
                sig_bytes = app.signer.sign_hash_hardware(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    data_hash=input_bytes,
                    ck_id=ck_id,
                    algo=algo,
                    is_simulated=token.is_simulated,
                )
            else:
                sig_bytes = app.signer.sign_data(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    raw_data=input_bytes,
                    algo=algo,
                    ck_id=ck_id,
                    is_simulated=token.is_simulated,
                )

            sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
            self._send_json(
                200,
                {
                    "status": 1,
                    "message": "Data signed successfully",
                    "signature": sig_b64,
                },
            )
        except Exception as e:
            logger.error(f"emBridge PKCSSign error: {e}")
            self._send_json(200, {"status": 0, "message": f"Signing error: {e}"})

    def _handle_emsigner_certificates(self):
        app = self.server_app
        certs = app.get_certificates()
        cert_items = []
        for c in certs:
            cert_items.append(
                {
                    "certificate": base64.b64encode(c.cert_der).decode("ascii"),
                    "alias": c.common_name,
                    "serialNumber": c.serial_number_hex,
                    "issuer": c.issuer_cn,
                    "validTo": c.valid_to.strftime("%d-%m-%Y %H:%M:%S") if hasattr(c, "valid_to") else "",
                    "pan": c.pan_number or "",
                }
            )
        self._send_json(200, {"status": "success", "certificates": cert_items})

    def _handle_emsigner_sign(self, payload: Dict[str, Any]):
        app = self.server_app
        token = app.get_primary_token()
        if not token:
            self._send_json(400, {"status": "error", "error": "No crypto token inserted."})
            return

        raw_input = payload.get("data") or payload.get("hash") or payload.get("signData") or ""
        pin = payload.get("pin") or payload.get("password") or ""
        algo = payload.get("algo") or "SHA256"

        try:
            input_bytes = base64.b64decode(raw_input)
        except Exception:
            input_bytes = raw_input.encode("utf-8")

        certs = app.get_certificates()
        cert = certs[0] if certs else None
        ck_id = cert.ck_id if cert else b""

        try:
            if len(input_bytes) in [20, 32, 64]:
                sig_bytes = app.signer.sign_hash_hardware(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    data_hash=input_bytes,
                    ck_id=ck_id,
                    algo=algo,
                    is_simulated=token.is_simulated,
                )
            else:
                sig_bytes = app.signer.sign_data(
                    token_id=token.token_id,
                    slot=payload.get("slot", 0),
                    pin=pin,
                    raw_data=input_bytes,
                    algo=algo,
                    ck_id=ck_id,
                    is_simulated=token.is_simulated,
                )

            sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
            self._send_json(200, {"status": "success", "signature": sig_b64})
        except Exception as e:
            self._send_json(500, {"status": "error", "error": str(e)})

    def _send_json(self, status: int, data: Dict[str, Any]):
        content = json.dumps(data, indent=2).encode("utf-8")
        self._set_cors_headers(status)
        self.wfile.write(content)

    def _log_request(self):
        msg = f"[{self.command}] {self.path} from {self.client_address[0]}"
        logger.info(msg)
        if self.server_app and self.server_app.log_callback:
            self.server_app.log_callback(msg)

    def log_message(self, format, *args):
        # Suppress default stderr output
        pass


class LoopbackServer:
    """Threaded local loopback HTTP gateway server supporting multi-port listeners."""

    def __init__(
        self,
        token_detector,
        pkcs11_mgr,
        cert_manager,
        pin_manager,
        signer,
        host: str = DEFAULT_LOOPBACK_HOST,
        port: int = DEFAULT_LOOPBACK_PORT,
    ):
        self.detector = token_detector
        self.pkcs11_mgr = pkcs11_mgr
        self.cert_manager = cert_manager
        self.pin_manager = pin_manager
        self.signer = signer
        self.host = host
        self.port = port
        self._servers: List[ThreadingHTTPServer] = []
        self._server_threads: List[threading.Thread] = []
        self.active_ports: List[int] = []
        self.log_callback: Optional[Callable[[str], None]] = None

    def get_primary_token(self):
        return self.detector.get_primary_token()

    def get_driver_statuses(self):
        return self.pkcs11_mgr.get_all_driver_statuses()

    def get_certificates(self):
        token = self.get_primary_token()
        if not token:
            return []
        if token.is_simulated or token.token_id == "SIMULATED":
            return [self.cert_manager.generate_simulated_dsc()]
        return self.cert_manager.get_token_certificates(token.token_id)

    def start(self) -> bool:
        """Start the loopback gateway across primary and government portal ports."""
        if self._servers:
            return True

        LoopbackRequestHandler.server_app = self
        ports_to_try = [self.port]
        for p in [1585, 26769, 26443]:
            if p not in ports_to_try:
                ports_to_try.append(p)

        bound_any = False
        for port in ports_to_try:
            try:
                server = ThreadingHTTPServer((self.host, port), LoopbackRequestHandler)
                thread = threading.Thread(
                    target=server.serve_forever, daemon=True, name=f"GatewayThread_{port}"
                )
                thread.start()
                self._servers.append(server)
                self._server_threads.append(thread)
                self.active_ports.append(port)
                bound_any = True
                logger.info(f"Gateway listening on http://{self.host}:{port}")
            except OSError as e:
                # Port already in use by external service (e.g. running emBridge/emSigner)
                logger.info(
                    f"Port {port} already bound by service or restricted: {e}. Falling back to active ports."
                )
            except Exception as e:
                logger.warning(f"Error binding port {port}: {e}")

        return bound_any

    def stop(self):
        """Stop all gateway server instances."""
        for server in self._servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception as e:
                logger.debug(f"Error closing server: {e}")
        self._servers.clear()

        for thread in self._server_threads:
            try:
                if thread.is_alive():
                    thread.join(timeout=1.0)
            except Exception:
                pass
        self._server_threads.clear()
        self.active_ports.clear()
        logger.info("All Gateway servers stopped.")

    def is_running(self) -> bool:
        return len(self._servers) > 0
