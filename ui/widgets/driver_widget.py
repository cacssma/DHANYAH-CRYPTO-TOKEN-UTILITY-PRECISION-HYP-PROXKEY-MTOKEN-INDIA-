"""
Dhanyah Crypto Utility - Dynamic Driver Discovery & System Health Widget
Displays installation and PKCS#11 validation status for all 4 vendors.
"""

from typing import List
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QFrame,
    QScrollArea,
)

from core.pkcs11_manager import PKCS11Manager, DriverStatus


class DriverWidget(QWidget):
    """Displays PKCS#11 middleware health and system driver discovery table."""

    def __init__(self, pkcs11_mgr: PKCS11Manager, parent=None):
        super().__init__(parent)
        self.pkcs11_mgr = pkcs11_mgr
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        card = QFrame()
        card.setProperty("class", "CardFrame")
        c_layout = QVBoxLayout(card)
        c_layout.setContentsMargins(18, 18, 18, 18)
        c_layout.setSpacing(12)

        top_row = QHBoxLayout()
        lbl_head = QLabel("PKCS#11 MIDDLEWARE & DRIVER HEALTH")
        lbl_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #ffffff;")
        top_row.addWidget(lbl_head)
        top_row.addStretch()

        btn_rescan = QPushButton("Rescan Drivers")
        btn_rescan.clicked.connect(self._rescan_drivers)
        top_row.addWidget(btn_rescan)

        c_layout.addLayout(top_row)

        lbl_desc = QLabel(
            "Dhanyah Crypto Utility dynamically searches Windows System32, SysWOW64, vendor Program Files, "
            "and Registry CSP keys to auto-load the correct PKCS#11 dynamic library for any connected token."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        c_layout.addWidget(lbl_desc)

        # Dynamic Driver Cards Container
        self.driver_container = QVBoxLayout()
        self.driver_container.setSpacing(10)
        c_layout.addLayout(self.driver_container)

        self._render_driver_cards()

        layout.addWidget(card)
        layout.addStretch()

    def _rescan_drivers(self):
        self.pkcs11_mgr.refresh_drivers()
        self._render_driver_cards()

    def _render_driver_cards(self):
        # Clear existing
        while self.driver_container.count():
            item = self.driver_container.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        statuses = self.pkcs11_mgr.get_all_driver_statuses()
        for d in statuses:
            d_card = QFrame()
            d_card.setProperty("class", "SubCardFrame")
            grid = QGridLayout(d_card)
            grid.setVerticalSpacing(4)
            grid.setHorizontalSpacing(12)

            # Row 0: Name & Status
            lbl_name = QLabel(d.token_name)
            lbl_name.setStyleSheet("font-size: 13px; font-weight: 700; color: #f8fafc;")
            grid.addWidget(lbl_name, 0, 0)

            badge = QLabel("VERIFIED & LOADABLE" if d.is_loadable else ("INSTALLED" if d.is_installed else "MISSING"))
            if d.is_loadable:
                badge.setProperty("class", "BadgeValid")
            elif d.is_installed:
                badge.setProperty("class", "BadgeWarning")
            else:
                badge.setProperty("class", "BadgeExpired")
            grid.addWidget(badge, 0, 1, Qt.AlignRight)

            # Row 1: Vendor & Bitness
            lbl_vendor = QLabel(f"Vendor: {d.vendor}  |  Arch: {d.bitness}")
            lbl_vendor.setStyleSheet("color: #64748b; font-size: 11px;")
            grid.addWidget(lbl_vendor, 1, 0, 1, 2)

            # Row 2: DLL Path
            path_str = d.dll_path or "No compatible DLL found"
            lbl_path = QLabel(f"Path: {path_str}")
            lbl_path.setStyleSheet("color: #38bdf8; font-family: monospace; font-size: 11px;")
            lbl_path.setTextInteractionFlags(Qt.TextSelectableByMouse)
            grid.addWidget(lbl_path, 2, 0, 1, 2)

            # Row 3: Status Message
            if d.error_message:
                lbl_msg = QLabel(d.error_message)
                lbl_msg.setStyleSheet("color: #94a3b8; font-size: 11px;")
                grid.addWidget(lbl_msg, 3, 0, 1, 2)

            self.driver_container.addWidget(d_card)
