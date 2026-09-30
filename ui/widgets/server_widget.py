"""
Dhanyah Crypto Utility - Local Loopback Gateway Controller Widget (Port 18200)
"""

import datetime
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QPlainTextEdit,
    QMessageBox,
)

from server.loopback_server import LoopbackServer


class ServerWidget(QWidget):
    """Loopback server monitor, control, and live HTTP request stream."""

    def __init__(self, server: LoopbackServer, parent=None):
        super().__init__(parent)
        self.server = server
        self._init_ui()
        # Connect log callback
        self.server.log_callback = self._on_server_log

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        # Server Control Card
        ctrl_card = QFrame()
        ctrl_card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(ctrl_card)
        c_layout.setContentsMargins(18, 18, 18, 18)
        c_layout.setSpacing(12)

        top_row = QHBoxLayout()
        lbl_head = QLabel("LOCAL HTTP LOOPBACK GATEWAY")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        top_row.addWidget(lbl_head)
        top_row.addStretch()

        self.lbl_server_status = QLabel("ONLINE")
        self.lbl_server_status.setProperty("class", "BadgeValid")
        top_row.addWidget(self.lbl_server_status)

        self.btn_toggle_server = QPushButton("Stop Service")
        self.btn_toggle_server.setProperty("class", "DangerButton")
        self.btn_toggle_server.clicked.connect(self._toggle_server)
        top_row.addWidget(self.btn_toggle_server)

        c_layout.addLayout(top_row)

        lbl_desc = QLabel(
            "Listens on localhost (port 18200) with CORS headers enabled. Web portals "
            "(MCA, GST, EPFO, Income Tax) and accounting tools (Tally, ERPs) can trigger "
            "hardware cryptographic signing via standard JSON REST endpoints."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        c_layout.addWidget(lbl_desc)

        # Endpoints summary
        ep_box = QFrame()
        ep_box.setProperty("class", "SubCardFrame")
        ep_layout = QGridLayout(ep_box)
        ep_layout.setVerticalSpacing(4)

        ep_layout.addWidget(QLabel("Gateway URL:"), 0, 0)
        lbl_url = QLabel(f"http://{self.server.host}:{self.server.port}")
        lbl_url.setStyleSheet("color: #38bdf8; font-family: monospace; font-weight: 600;")
        ep_layout.addWidget(lbl_url, 0, 1)

        ep_layout.addWidget(QLabel("Endpoints:"), 1, 0)
        lbl_eps = QLabel("GET /status   |   GET /certificates   |   POST /sign/hash   |   POST /sign/pdf")
        lbl_eps.setStyleSheet("color: #a5f3fc; font-family: monospace; font-size: 11px;")
        ep_layout.addWidget(lbl_eps, 1, 1)

        c_layout.addWidget(ep_box)
        layout.addWidget(ctrl_card)

        # Live Request Logs Card
        log_card = QFrame()
        log_card.setProperty("class", "CardFrame")
        l_layout = QVBoxLayout(log_card)
        l_layout.setContentsMargins(18, 18, 18, 18)
        l_layout.setSpacing(10)

        log_head = QHBoxLayout()
        lbl_log_title = QLabel("LIVE REQUEST STREAM & GATEWAY LOGS")
        lbl_log_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #94a3b8;")
        log_head.addWidget(lbl_log_title)
        log_head.addStretch()

        btn_clear = QPushButton("Clear Logs")
        btn_clear.setFixedWidth(80)
        btn_clear.clicked.connect(self._clear_logs)
        log_head.addWidget(btn_clear)

        btn_copy = QPushButton("Copy URL")
        btn_copy.setFixedWidth(80)
        btn_copy.clicked.connect(self._copy_url)
        log_head.addWidget(btn_copy)

        l_layout.addLayout(log_head)

        self.text_logs = QPlainTextEdit()
        self.text_logs.setReadOnly(True)
        self.text_logs.setStyleSheet(
            "font-family: monospace; font-size: 11px; background-color: #0b1120; color: #e2e8f0; border-radius: 6px;"
        )
        self.text_logs.appendPlainText(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Gateway service ready.")
        l_layout.addWidget(self.text_logs)

        layout.addWidget(log_card)

    def _toggle_server(self):
        if self.server.is_running():
            self.server.stop()
            self.lbl_server_status.setText("STOPPED")
            self.lbl_server_status.setProperty("class", "BadgeExpired")
            self.btn_toggle_server.setText("Start Service")
            self.btn_toggle_server.setProperty("class", "SuccessButton")
            self._log_local("Gateway service stopped by user.")
        else:
            ok = self.server.start()
            if ok:
                self.lbl_server_status.setText("ONLINE")
                self.lbl_server_status.setProperty("class", "BadgeValid")
                self.btn_toggle_server.setText("Stop Service")
                self.btn_toggle_server.setProperty("class", "DangerButton")
                self._log_local(f"Gateway service resumed on port {self.server.port}.")
            else:
                QMessageBox.critical(self, "Server Error", f"Failed to bind port {self.server.port}.")

        self.lbl_server_status.setStyleSheet("")
        self.btn_toggle_server.setStyleSheet("")

    def _on_server_log(self, msg: str):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.text_logs.appendPlainText(f"[{timestamp}] {msg}")

    def _log_local(self, msg: str):
        self._on_server_log(msg)

    def _clear_logs(self):
        self.text_logs.clear()

    def _copy_url(self):
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(f"http://{self.server.host}:{self.server.port}")
