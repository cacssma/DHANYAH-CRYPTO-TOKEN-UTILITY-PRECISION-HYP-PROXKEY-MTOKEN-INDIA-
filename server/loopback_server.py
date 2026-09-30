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

        if path in ["/", "/status", "/health"]:
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
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path in ["/verify/pin", "/pin/verify"]:
            self._handle_verify_pin(payload)
        elif path in ["/sign/hash", "/hash/sign"]:
            self._handle_sign_hash(payload)
        elif path in ["/sign/pdf", "/pdf/sign"]:
            self._handle_sign_pdf(payload)
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
    """Threaded local loopback HTTP server."""

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
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
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
        """Start the loopback server in background thread."""
        if self._httpd is not None:
            return True

        LoopbackRequestHandler.server_app = self
        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), LoopbackRequestHandler)
            self._server_thread = threading.Thread(
                target=self._httpd.serve_forever, daemon=True, name="LoopbackServerThread"
            )
            self._server_thread.start()
            logger.info(f"Loopback Server listening on http://{self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start loopback server on port {self.port}: {e}")
            self._httpd = None
            return False

    def stop(self):
        """Stop the loopback server."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
            if self._server_thread and self._server_thread.is_alive():
                self._server_thread.join(timeout=1.0)
            logger.info("Loopback Server stopped.")

    def is_running(self) -> bool:
        return self._httpd is not None
