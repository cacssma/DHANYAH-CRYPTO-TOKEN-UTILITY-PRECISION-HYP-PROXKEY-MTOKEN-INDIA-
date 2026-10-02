"""
Dhanyah Crypto Utility - Token Hardware Banner & Monitor Widget
"""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QIcon, QClipboard, QGuiApplication
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QComboBox,
    QFrame,
)

from core.constants import (
    TOKEN_PROFILES,
    TOKEN_HYP2003,
    TOKEN_MTOKEN,
    TOKEN_PROXKEY,
    TOKEN_INNAIT,
)
from core.token_detector import DetectedToken


class TokenBannerWidget(QFrame):
    """Real-time token status banner and hardware monitor."""

    simulation_changed = Signal(str)  # Emits token_id or ""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setProperty("class", "CardFrame")
        self._current_token: DetectedToken = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Top Header Row: Title, Status Pill & Simulation Mode
        header_row = QHBoxLayout()
        self.lbl_title = QLabel("HARDWARE TOKEN MONITOR")
        self.lbl_title.setStyleSheet("font-size: 11px; font-weight: 700; color: #94a3b8; letter-spacing: 1px;")
        header_row.addWidget(self.lbl_title)

        header_row.addStretch()

        self.lbl_status_pill = QLabel("NO TOKEN DETECTED")
        self.lbl_status_pill.setProperty("class", "BadgeWarning")
        header_row.addWidget(self.lbl_status_pill)

        # Simulation Mode selector for quick testing
        lbl_sim = QLabel("Demo/Sim:")
        lbl_sim.setStyleSheet("color: #94a3b8; font-size: 11px; margin-left: 10px;")
        header_row.addWidget(lbl_sim)

        self.combo_sim = QComboBox()
        self.combo_sim.addItem("Live Hardware", "")
        self.combo_sim.addItem("Simulate HYP 2003", TOKEN_HYP2003)
        self.combo_sim.addItem("Simulate mToken CryptoID", TOKEN_MTOKEN)
        self.combo_sim.addItem("Simulate Watchdata ProxKey", TOKEN_PROXKEY)
        self.combo_sim.addItem("Simulate Precision InnaITKey", TOKEN_INNAIT)
        self.combo_sim.currentIndexChanged.connect(self._on_sim_changed)
        header_row.addWidget(self.combo_sim)

        layout.addLayout(header_row)

        # Main Info Grid
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(8)

        # Token Name
        lbl_token_title = QLabel("Device:")
        lbl_token_title.setStyleSheet("color: #64748b; font-weight: 600;")
        self.lbl_device_name = QLabel("Waiting for crypto token insertion...")
        self.lbl_device_name.setStyleSheet("font-size: 16px; font-weight: 700; color: #f8fafc;")
        self.grid.addWidget(lbl_token_title, 0, 0)
        self.grid.addWidget(self.lbl_device_name, 0, 1)

        # Reader Name
        lbl_reader_title = QLabel("PC/SC Reader:")
        lbl_reader_title.setStyleSheet("color: #64748b; font-weight: 600;")
        self.lbl_reader_name = QLabel("None")
        self.lbl_reader_name.setStyleSheet("color: #cbd5e1; font-family: monospace;")
        self.grid.addWidget(lbl_reader_title, 1, 0)
        self.grid.addWidget(self.lbl_reader_name, 1, 1)

        # ATR row with copy button
        lbl_atr_title = QLabel("Smart Card ATR:")
        lbl_atr_title.setStyleSheet("color: #64748b; font-weight: 600;")
        atr_layout = QHBoxLayout()
        self.lbl_atr = QLabel("None")
        self.lbl_atr.setStyleSheet("color: #38bdf8; font-family: monospace; font-size: 11px;")
        atr_layout.addWidget(self.lbl_atr)

        self.btn_copy_atr = QPushButton("Copy ATR")
        self.btn_copy_atr.setFixedWidth(80)
        self.btn_copy_atr.setStyleSheet("font-size: 10px; padding: 3px 6px; height: 16px;")
        self.btn_copy_atr.clicked.connect(self._copy_atr)
        atr_layout.addWidget(self.btn_copy_atr)
        atr_layout.addStretch()

        self.grid.addWidget(lbl_atr_title, 2, 0)
        self.grid.addLayout(atr_layout, 2, 1)

        # Serial & FIPS rating
        lbl_specs_title = QLabel("Specifications:")
        lbl_specs_title.setStyleSheet("color: #64748b; font-weight: 600;")
        self.lbl_specs = QLabel("Security: FIPS 140-2/3 Level 3 | RSA 2048/4096-bit")
        self.lbl_specs.setStyleSheet("color: #94a3b8;")
        self.grid.addWidget(lbl_specs_title, 3, 0)
        self.grid.addWidget(self.lbl_specs, 3, 1)

        layout.addLayout(self.grid)

        # Driver Footer Banner
        self.driver_banner = QFrame()
        self.driver_banner.setProperty("class", "SubCardFrame")
        db_layout = QHBoxLayout(self.driver_banner)
        db_layout.setContentsMargins(10, 6, 10, 6)

        self.lbl_driver_info = QLabel("Driver: Scanning PKCS#11 subsystem...")
        self.lbl_driver_info.setStyleSheet("color: #94a3b8; font-size: 12px;")
        db_layout.addWidget(self.lbl_driver_info)

        layout.addWidget(self.driver_banner)

    def update_token(self, token: DetectedToken, driver_path: str = ""):
        """Update display with detected token details."""
        self._current_token = token
        if not token:
            self.lbl_status_pill.setText("NO TOKEN INSERTED")
            self.lbl_status_pill.setProperty("class", "BadgeWarning")
            self.lbl_status_pill.setStyleSheet("")
            self.lbl_device_name.setText("Please insert a USB Crypto Token (HYP 2003, mToken, ProxKey, InnaITKey)")
            self.lbl_reader_name.setText("No PC/SC Reader Active")
            self.lbl_atr.setText("N/A")
            self.lbl_specs.setText("Security: FIPS 140-2/3 Level 3 (Waiting for connection)")
            self.lbl_driver_info.setText("System: Smart Card Service running. Ready for token hotplug.")
        # Token Connected
        if token.is_simulated:
            self.lbl_status_pill.setText("SIMULATION MODE")
            self.lbl_status_pill.setProperty("class", "BadgeInfo")
            self.lbl_status_pill.setStyleSheet("background-color: #0284c7; color: #ffffff; padding: 4px 10px; border-radius: 10px; font-weight: bold;")
            sim_tag = " [DEMO SIMULATION]"
        else:
            # Physical Hardware Token
            self.combo_sim.blockSignals(True)
            self.combo_sim.setCurrentIndex(0)  # Live Hardware
            self.combo_sim.blockSignals(False)

            self.lbl_status_pill.setText("● ACTIVE HARDWARE TOKEN")
            self.lbl_status_pill.setProperty("class", "BadgeValid")
            self.lbl_status_pill.setStyleSheet("background-color: #16a34a; color: #ffffff; padding: 4px 10px; border-radius: 10px; font-weight: bold;")
            sim_tag = " [PHYSICAL HARDWARE]"

        self.lbl_device_name.setText(f"{token.name}{sim_tag}")
        self.lbl_reader_name.setText(token.reader_name)
        self.lbl_atr.setText(token.atr or "Simulated ATR Signature")
        self.lbl_specs.setText(f"Vendor: {token.vendor}  |  Level: {token.fips_level}  |  Serial: {token.serial_number}")

        if driver_path:
            self.lbl_driver_info.setText(f"Active PKCS#11 Library: {driver_path}")
        else:
            self.lbl_driver_info.setText(f"Subsystem Status: Native MiniDriver & PKCS#11 Active for {token.name}")

    def _copy_atr(self):
        text = self.lbl_atr.text()
        if text and text != "N/A" and text != "None":
            clipboard = QGuiApplication.clipboard()
            clipboard.setText(text)
            self.btn_copy_atr.setText("Copied!")
            from PySide6.QtCore import QTimer
            QTimer.singleShot(1500, lambda: self.btn_copy_atr.setText("Copy ATR"))

    def _on_sim_changed(self, index: int):
        token_id = self.combo_sim.currentData()
        self.simulation_changed.emit(token_id)
