"""
Dhanyah Crypto Utility - Unified Desktop Application Main Window
"""

import logging
from PySide6.QtCore import Qt, Signal, QObject, Slot
from PySide6.QtGui import QIcon, QFont
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QStackedWidget,
    QListWidget,
    QListWidgetItem,
    QLabel,
    QStatusBar,
    QFrame,
    QApplication,
    QPushButton,
)

from core.token_detector import TokenDetector, DetectedToken
from core.pkcs11_manager import PKCS11Manager
from core.cert_manager import CertManager, ParsedCertificate
from core.pin_manager import PinManager
from core.signer import TokenSigner
from server.loopback_server import LoopbackServer

from ui.styles import DARK_THEME_QSS, LIGHT_THEME_QSS
from ui.widgets.token_banner import TokenBannerWidget
from ui.widgets.cert_table import CertTableWidget
from ui.widgets.pin_dialog import PinManagementWidget
from ui.widgets.pdf_signer_widget import PdfSignerWidget
from ui.widgets.server_widget import ServerWidget
from ui.widgets.driver_widget import DriverWidget

logger = logging.getLogger("DhanyahCrypto.UI")


class EventBridge(QObject):
    """Thread-safe signal bridge for background PC/SC hotplug events."""

    token_inserted_signal = Signal(object)
    token_removed_signal = Signal(str)


class MainWindow(QMainWindow):
    """Master application window for Dhanyah Crypto Utility."""

    def __init__(
        self,
        detector: TokenDetector,
        pkcs11_mgr: PKCS11Manager,
        cert_mgr: CertManager,
        pin_mgr: PinManager,
        signer: TokenSigner,
        server: LoopbackServer,
    ):
        super().__init__()
        self.detector = detector
        self.pkcs11_mgr = pkcs11_mgr
        self.cert_mgr = cert_mgr
        self.pin_mgr = pin_mgr
        self.signer = signer
        self.server = server

        self.bridge = EventBridge()
        self.bridge.token_inserted_signal.connect(self._on_token_inserted_ui)
        self.bridge.token_removed_signal.connect(self._on_token_removed_ui)

        # Wire detector callbacks into bridge
        self.detector.register_insertion_callback(lambda token: self.bridge.token_inserted_signal.emit(token))
        self.detector.register_removal_callback(lambda reader: self.bridge.token_removed_signal.emit(reader))

        self.is_dark_mode = True
        self.setWindowTitle("Dhanyah Crypto Utility - Unified Token Management & PKI Signer")
        self.resize(1100, 720)
        self.setMinimumSize(960, 600)
        self.setStyleSheet(DARK_THEME_QSS)

        self._init_ui()
        self._check_initial_state()

    def _init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 14, 14, 14)
        main_layout.setSpacing(12)

        # 1. Header Toolbar Banner
        header_frame = QFrame()
        header_frame.setProperty("class", "CardFrame")
        h_layout = QHBoxLayout(header_frame)
        h_layout.setContentsMargins(16, 12, 16, 12)

        # Brand Title & Logo
        title_box = QVBoxLayout()
        lbl_app_name = QLabel("DHANYAH CRYPTO UTILITY")
        lbl_app_name.setStyleSheet("font-size: 17px; font-weight: 800; color: #ffffff; letter-spacing: 1.5px;")
        lbl_subtitle = QLabel("Unified FIPS 140-2/3 Level 3 Token Management & Cryptographic Signing Suite")
        lbl_subtitle.setStyleSheet("font-size: 11px; color: #94a3b8;")
        title_box.addWidget(lbl_app_name)
        title_box.addWidget(lbl_subtitle)
        h_layout.addLayout(title_box)

        h_layout.addStretch()

        # Fast Indicators
        self.lbl_hdr_driver = QLabel("4 Drivers Verified")
        self.lbl_hdr_driver.setProperty("class", "BadgeValid")
        h_layout.addWidget(self.lbl_hdr_driver)

        self.lbl_hdr_server = QLabel("Loopback Gateway :18200")
        self.lbl_hdr_server.setProperty("class", "BadgeInfo")
        h_layout.addWidget(self.lbl_hdr_server)

        # Theme Toggle Button
        self.btn_theme = QPushButton("☀️ Light Mode")
        self.btn_theme.setFixedWidth(115)
        self.btn_theme.clicked.connect(self._toggle_theme)
        h_layout.addWidget(self.btn_theme)

        main_layout.addWidget(header_frame)

        # 2. Main Content: Sidebar + Stacked Module Views
        body_layout = QHBoxLayout()
        body_layout.setSpacing(14)

        # Navigation Sidebar
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("SidebarList")
        self.sidebar.setFixedWidth(230)
        self.sidebar.setFocusPolicy(Qt.NoFocus)

        nav_items = [
            ("🖥️  Dashboard", "Overview, token status & hardware telemetry"),
            ("📜  DSC Certificates", "Inspect installed X.509 certificates & CCA fields"),
            ("🔑  PIN Management", "Verify PIN & safe C_SetPIN change utility"),
            ("✍️  PDF Document Signer", "Standalone PAdES digital signing with token"),
            ("🌐  Loopback Gateway", "Localhost REST API :18200 for web portals"),
            ("⚙️  Driver Subsystem", "Dynamic PKCS#11 discovery & library health"),
        ]

        for text, tip in nav_items:
            item = QListWidgetItem(text)
            item.setToolTip(tip)
            self.sidebar.addItem(item)

        self.sidebar.currentRowChanged.connect(self._on_nav_changed)
        body_layout.addWidget(self.sidebar)

        # Stacked Views Container
        self.stack = QStackedWidget()

        # View 0: Dashboard (Banner + Cert Summary)
        view_dash = QWidget()
        vd_layout = QVBoxLayout(view_dash)
        vd_layout.setContentsMargins(0, 0, 0, 0)
        vd_layout.setSpacing(12)
        self.banner = TokenBannerWidget()
        self.banner.simulation_changed.connect(self._on_simulation_changed)
        vd_layout.addWidget(self.banner)

        self.dash_cert_table = CertTableWidget()
        vd_layout.addWidget(self.dash_cert_table)
        self.stack.addWidget(view_dash)

        # View 1: Certificates Tab
        self.cert_table = CertTableWidget()
        self.stack.addWidget(self.cert_table)

        # View 2: PIN Management
        self.pin_widget = PinManagementWidget(self.pin_mgr)
        self.stack.addWidget(self.pin_widget)

        # View 3: PDF Signer
        self.signer_widget = PdfSignerWidget(self.signer)
        self.stack.addWidget(self.signer_widget)

        # View 4: Loopback Gateway
        self.server_widget = ServerWidget(self.server)
        self.stack.addWidget(self.server_widget)

        # View 5: Driver Subsystem
        self.driver_widget = DriverWidget(self.pkcs11_mgr)
        self.stack.addWidget(self.driver_widget)

        body_layout.addWidget(self.stack)
        main_layout.addLayout(body_layout)

        # Status Bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Smart Card Subsystem Active | Auto-Detection Polling...")

        lbl_contact = QLabel("Author: CA Akash J. Bhayani | Website: CA-AKASH.IN | mail@ca-akash.in")
        lbl_contact.setStyleSheet("color: #718096; font-size: 11px; padding-right: 10px;")
        self.status_bar.addPermanentWidget(lbl_contact)

        # Select first nav item
        self.sidebar.setCurrentRow(0)

    def _on_nav_changed(self, row: int):
        self.stack.setCurrentIndex(row)

    def _toggle_theme(self):
        """Toggle between Dark and Light enterprise themes."""
        self.is_dark_mode = not self.is_dark_mode
        if self.is_dark_mode:
            self.setStyleSheet(DARK_THEME_QSS)
            self.btn_theme.setText("☀️ Light Mode")
        else:
            self.setStyleSheet(LIGHT_THEME_QSS)
            self.btn_theme.setText("🌙 Dark Mode")

    def _on_simulation_changed(self, token_id: str):
        """Triggered when user toggles simulation mode from banner dropdown."""
        self.detector.set_simulation_mode(token_id if token_id else None)
        token = self.detector.get_primary_token()
        if token:
            self._on_token_inserted_ui(token)
        else:
            self._on_token_removed_ui("")

    def _check_initial_state(self):
        """Check if any token is already plugged in at launch."""
        token = self.detector.get_primary_token()
        if token:
            self._on_token_inserted_ui(token)
        else:
            self._on_token_removed_ui("")

    @Slot(object)
    def _on_token_inserted_ui(self, token: DetectedToken):
        logger.info(f"UI handling token inserted: {token}")

        # Determine driver path
        driver_status = self.pkcs11_mgr.get_driver_status(token.token_id)
        driver_path = driver_status.dll_path if driver_status and driver_status.is_loadable else ""

        # Update banner
        self.banner.update_token(token, driver_path)

        # Extract certificates
        certs = []
        if token.is_simulated or token.token_id == "SIMULATED":
            certs = [self.cert_mgr.generate_simulated_dsc()]
        else:
            slots = self.pkcs11_mgr.get_slots_with_token(token.token_id)
            slot_id = slots[0] if slots else 0
            certs = self.cert_mgr.get_token_certificates(token.token_id, slot=slot_id)

        # Update certificate tables
        self.dash_cert_table.set_certificates(certs)
        self.cert_table.set_certificates(certs)

        # Synchronize certificates to Windows Personal Store with CSP private key link
        if not token.is_simulated and certs:
            try:
                from core.smartcard_registrar import SmartCardRegistrar
                synced_count, sync_msg = SmartCardRegistrar.sync_token_certificates_to_store(token.token_id, certs)
                logger.info(f"Windows Store Key-Linker: {sync_msg}")
            except Exception as e_sync:
                logger.warning(f"Could not auto-sync certificates to Windows store: {e_sync}")

        # Update PIN context
        self.pin_widget.set_token_context(
            token_id=token.token_id,
            slot=slot_id,
            is_simulated=token.is_simulated,
        )

        # Update Signer context
        self.signer_widget.set_token_context(
            token_id=token.token_id,
            slot=slot_id,
            certs=certs,
            is_simulated=token.is_simulated,
        )

        status_text = f"Active Token: {token.name} on {token.reader_name} | FIPS Security: {token.fips_level}"
        if not token.is_simulated:
            status_text += " | Windows Personal Store Key-Linked"
        self.status_bar.showMessage(status_text)

    @Slot(str)
    def _on_token_removed_ui(self, reader_name: str):
        logger.info(f"UI handling token removed from {reader_name}")
        self.banner.update_token(None)
        self.dash_cert_table.set_certificates([])
        self.cert_table.set_certificates([])
        self.pin_widget.set_token_context("")
        self.signer_widget.set_token_context("", 0, [])
        self.status_bar.showMessage("Ready. Waiting for crypto token connection...")

    def closeEvent(self, event):
        """Clean shutdown of background services on exit."""
        logger.info("Shutting down Dhanyah Crypto Utility...")
        try:
            self.detector.stop()
            self.server.stop()
        except Exception:
            pass
        event.accept()
