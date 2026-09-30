"""
Dhanyah Crypto Utility - PDF Document Signer Widget (PAdES Hardware Signing)
"""

import os
import subprocess
from typing import List, Optional
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QComboBox,
    QFileDialog,
    QFrame,
    QMessageBox,
    QProgressBar,
)

from core.cert_manager import ParsedCertificate
from core.signer import TokenSigner, SignResult


class PdfSignerWidget(QWidget):
    """PDF signing utility widget with token certificate selection and metadata options."""

    def __init__(self, signer: TokenSigner, parent=None):
        super().__init__(parent)
        self.signer = signer
        self._certificates: List[ParsedCertificate] = []
        self._current_token_id = ""
        self._current_slot = 0
        self._is_simulated = False
        self._signed_path = ""
        self._init_ui()

    def set_token_context(
        self,
        token_id: str,
        slot: int,
        certs: List[ParsedCertificate],
        is_simulated: bool = False,
    ):
        self._current_token_id = token_id
        self._current_slot = slot
        self._certificates = certs
        self._is_simulated = is_simulated

        self.combo_certs.clear()
        for c in certs:
            pan_str = f" [PAN: {c.pan_number}]" if c.pan_number else ""
            self.combo_certs.addItem(f"{c.common_name} ({c.cert_class}){pan_str}", c)

        has_certs = len(certs) > 0
        self.btn_sign.setEnabled(has_certs)
        if not has_certs:
            self.lbl_status.setText("No signing certificate available. Insert token or enable Demo mode.")
            self.lbl_status.setProperty("class", "BadgeWarning")
        else:
            self.lbl_status.setText(f"Ready to sign with {len(certs)} certificate(s) loaded.")
            self.lbl_status.setProperty("class", "BadgeValid")
        self.lbl_status.setStyleSheet("")

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        # Card Container
        card = QFrame()
        card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(20, 20, 20, 20)
        c_layout.setSpacing(14)

        lbl_head = QLabel("PADES PDF DOCUMENT DIGITAL SIGNER")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        c_layout.addWidget(lbl_head)

        lbl_desc = QLabel(
            "Cryptographically signs PDF documents using SHA-256 with the RSA private key "
            "stored onboard the FIPS Level 3 crypto token (PAdES / adbe.pkcs7.detached)."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        c_layout.addWidget(lbl_desc)

        grid = QGridLayout()
        grid.setVerticalSpacing(10)
        grid.setHorizontalSpacing(14)

        # 1. Input PDF File
        lbl_pdf = QLabel("Input PDF File:")
        lbl_pdf.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_pdf, 0, 0)

        pdf_row = QHBoxLayout()
        self.edit_pdf_path = QLineEdit()
        self.edit_pdf_path.setPlaceholderText("Select or drop a PDF file to sign...")
        pdf_row.addWidget(self.edit_pdf_path)

        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self._browse_pdf)
        pdf_row.addWidget(btn_browse)
        grid.addLayout(pdf_row, 0, 1)

        # 2. Certificate Selector
        lbl_cert = QLabel("Signing Certificate:")
        lbl_cert.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_cert, 1, 0)

        self.combo_certs = QComboBox()
        grid.addWidget(self.combo_certs, 1, 1)

        # 3. Token PIN
        lbl_pin = QLabel("Token User PIN:")
        lbl_pin.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_pin, 2, 0)

        pin_row = QHBoxLayout()
        self.edit_pin = QLineEdit()
        self.edit_pin.setEchoMode(QLineEdit.Password)
        self.edit_pin.setPlaceholderText("Enter token PIN to unlock private key for signing")
        pin_row.addWidget(self.edit_pin)
        grid.addLayout(pin_row, 2, 1)

        # 4. Reason
        lbl_reason = QLabel("Signing Reason:")
        lbl_reason.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_reason, 3, 0)

        self.combo_reason = QComboBox()
        self.combo_reason.setEditable(True)
        self.combo_reason.addItem("I have reviewed and approved this document")
        self.combo_reason.addItem("MCA / Registrar of Companies Filing")
        self.combo_reason.addItem("GST Return & Invoice Attestation")
        self.combo_reason.addItem("Income Tax Return e-Verification")
        self.combo_reason.addItem("Tender Submission / e-Procurement")
        self.combo_reason.addItem("General Document Verification")
        grid.addWidget(self.combo_reason, 3, 1)

        # 5. Location
        lbl_loc = QLabel("Signing Location:")
        lbl_loc.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_loc, 4, 0)

        self.edit_loc = QLineEdit("India")
        grid.addWidget(self.edit_loc, 4, 1)

        # 6. Output PDF File
        lbl_out = QLabel("Save Signed PDF To:")
        lbl_out.setStyleSheet("font-weight: 600; color: #cbd5e1;")
        grid.addWidget(lbl_out, 5, 0)

        out_row = QHBoxLayout()
        self.edit_out_path = QLineEdit()
        self.edit_out_path.setPlaceholderText("Auto-generated: <filename>_signed.pdf")
        out_row.addWidget(self.edit_out_path)

        btn_browse_out = QPushButton("Change...")
        btn_browse_out.clicked.connect(self._browse_out)
        out_row.addWidget(btn_browse_out)
        grid.addLayout(out_row, 5, 1)

        c_layout.addLayout(grid)

        # Sign Action Button & Progress
        act_row = QHBoxLayout()
        self.btn_sign = QPushButton("Sign PDF Document")
        self.btn_sign.setProperty("class", "PrimaryButton")
        self.btn_sign.setMinimumHeight(38)
        self.btn_sign.clicked.connect(self._on_sign_clicked)
        act_row.addWidget(self.btn_sign)

        self.btn_open_signed = QPushButton("Open Signed PDF")
        self.btn_open_signed.setProperty("class", "SuccessButton")
        self.btn_open_signed.setMinimumHeight(38)
        self.btn_open_signed.setVisible(False)
        self.btn_open_signed.clicked.connect(self._open_signed_pdf)
        act_row.addWidget(self.btn_open_signed)

        c_layout.addLayout(act_row)

        # Status Label
        self.lbl_status = QLabel("Select a PDF file and enter PIN to sign.")
        self.lbl_status.setProperty("class", "BadgeInfo")
        self.lbl_status.setWordWrap(True)
        c_layout.addWidget(self.lbl_status)

        layout.addWidget(card)

    def _browse_pdf(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PDF to Sign",
            "",
            "PDF Documents (*.pdf);;All Files (*)",
        )
        if file_path:
            self.edit_pdf_path.setText(file_path)
            # Default output path
            base, ext = os.path.splitext(file_path)
            out_default = f"{base}_signed{ext}"
            self.edit_out_path.setText(out_default)

    def _browse_out(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Signed PDF",
            self.edit_out_path.text() or "document_signed.pdf",
            "PDF Documents (*.pdf);;All Files (*)",
        )
        if file_path:
            self.edit_out_path.setText(file_path)

    def _on_sign_clicked(self):
        in_path = self.edit_pdf_path.text().strip()
        out_path = self.edit_out_path.text().strip()
        pin = self.edit_pin.text()
        cert: ParsedCertificate = self.combo_certs.currentData()

        if not in_path or not os.path.exists(in_path):
            QMessageBox.warning(self, "Invalid File", "Please select a valid input PDF file.")
            return

        if not out_path:
            base, ext = os.path.splitext(in_path)
            out_path = f"{base}_signed{ext}"
            self.edit_out_path.setText(out_path)

        if not cert:
            QMessageBox.warning(self, "No Certificate", "Please select a signing certificate.")
            return

        if not pin:
            QMessageBox.warning(self, "PIN Required", "Please enter the Token PIN to authorize hardware signing.")
            return

        self.btn_sign.setEnabled(False)
        self.lbl_status.setText("Connecting to crypto token and computing PAdES signature...")
        self.lbl_status.setProperty("class", "BadgeInfo")
        self.lbl_status.setStyleSheet("")

        try:
            res: SignResult = self.signer.sign_pdf(
                input_pdf_path=in_path,
                output_pdf_path=out_path,
                token_id=self._current_token_id or "SIMULATED",
                slot=self._current_slot,
                pin=pin,
                cert=cert,
                reason=self.combo_reason.currentText(),
                location=self.edit_loc.text(),
                is_simulated=self._is_simulated,
            )

            if res.success:
                self._signed_path = out_path
                self.lbl_status.setText(f"✓ PDF digitally signed successfully: {out_path}")
                self.lbl_status.setProperty("class", "BadgeValid")
                self.btn_open_signed.setVisible(True)
                QMessageBox.information(
                    self,
                    "Signing Complete",
                    f"Document successfully signed!\nSigner: {cert.common_name}\nOutput: {out_path}",
                )
            else:
                self.lbl_status.setText(f"Signing failed: {res.error_message}")
                self.lbl_status.setProperty("class", "BadgeExpired")
                QMessageBox.critical(self, "Signing Error", f"Failed to sign PDF:\n{res.error_message}")
        finally:
            self.btn_sign.setEnabled(True)
            self.lbl_status.setStyleSheet("")

    def _open_signed_pdf(self):
        if self._signed_path and os.path.exists(self._signed_path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._signed_path))
