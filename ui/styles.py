"""
Dhanyah Crypto Utility - Modern Professional QSS Theme & Stylesheet
Enterprise Dark/Navy styling with clean typography and status badges.
"""

DARK_THEME_QSS = """
/* Global Window & Typography */
QMainWindow, QDialog, QWidget {
    background-color: #0f172a;
    color: #f1f5f9;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

/* Sidebar & Navigation */
QListWidget#SidebarList {
    background-color: #1e293b;
    border: none;
    border-right: 1px solid #334155;
    padding-top: 12px;
    font-size: 14px;
    font-weight: 500;
}

QListWidget#SidebarList::item {
    height: 48px;
    padding-left: 18px;
    margin: 4px 10px;
    border-radius: 8px;
    color: #94a3b8;
}

QListWidget#SidebarList::item:hover {
    background-color: #334155;
    color: #f8fafc;
}

QListWidget#SidebarList::item:selected {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
}

/* Cards & Containers */
QFrame.CardFrame {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 16px;
}

QFrame.SubCardFrame {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px;
}

/* Section Headings */
QLabel.HeaderTitle {
    font-size: 18px;
    font-weight: 700;
    color: #ffffff;
}

QLabel.SectionTitle {
    font-size: 15px;
    font-weight: 600;
    color: #e2e8f0;
}

QLabel.SubText {
    font-size: 12px;
    color: #94a3b8;
}

/* Status Badges */
QLabel.BadgeValid {
    background-color: #064e3b;
    color: #34d399;
    border: 1px solid #059669;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeWarning {
    background-color: #78350f;
    color: #fcd34d;
    border: 1px solid #d97706;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeExpired {
    background-color: #7f1d1d;
    color: #fca5a5;
    border: 1px solid #dc2626;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeInfo {
    background-color: #1e3a8a;
    color: #93c5fd;
    border: 1px solid #2563eb;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

/* Primary and Action Buttons */
QPushButton {
    background-color: #334155;
    color: #f8fafc;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #475569;
    border-color: #64748b;
}

QPushButton:pressed {
    background-color: #1e293b;
}

QPushButton:disabled {
    background-color: #1e293b;
    color: #64748b;
    border-color: #334155;
}

QPushButton.PrimaryButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #3b82f6;
    font-weight: 600;
}

QPushButton.PrimaryButton:hover {
    background-color: #1d4ed8;
    border-color: #60a5fa;
}

QPushButton.SuccessButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #10b981;
    font-weight: 600;
}

QPushButton.SuccessButton:hover {
    background-color: #047857;
}

QPushButton.DangerButton {
    background-color: #dc2626;
    color: #ffffff;
    border: 1px solid #ef4444;
    font-weight: 600;
}

QPushButton.DangerButton:hover {
    background-color: #b91c1c;
}

/* Form Inputs */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #0f172a;
    border: 1px solid #475569;
    border-radius: 6px;
    color: #f8fafc;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: #2563eb;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #3b82f6;
    background-color: #111e38;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

/* Tables */
QTableWidget {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    gridline-color: #334155;
    color: #f8fafc;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    font-weight: 600;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #334155;
    border-right: 1px solid #1e293b;
}

/* Status Bar */
QStatusBar {
    background-color: #0f172a;
    border-top: 1px solid #334155;
    color: #94a3b8;
    font-size: 12px;
}

/* ScrollBars */
QScrollBar:vertical {
    border: none;
    background-color: #0f172a;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #334155;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #475569;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #334155;
    border-radius: 8px;
    background-color: #1e293b;
    padding: 10px;
}

QTabBar::tab {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    color: #94a3b8;
}

QTabBar::tab:selected {
    background-color: #1e293b;
    color: #38bdf8;
    border-bottom: 2px solid #38bdf8;
    font-weight: 600;
}
"""

LIGHT_THEME_QSS = """
/* Global Window & Typography (Light Mode) */
QMainWindow, QDialog, QWidget {
    background-color: #f1f5f9;
    color: #0f172a;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}

/* Sidebar & Navigation */
QListWidget#SidebarList {
    background-color: #ffffff;
    border: none;
    border-right: 1px solid #e2e8f0;
    padding-top: 12px;
    font-size: 14px;
    font-weight: 500;
}

QListWidget#SidebarList::item {
    height: 48px;
    padding-left: 18px;
    margin: 4px 10px;
    border-radius: 8px;
    color: #475569;
}

QListWidget#SidebarList::item:hover {
    background-color: #f1f5f9;
    color: #0f172a;
}

QListWidget#SidebarList::item:selected {
    background-color: #2563eb;
    color: #ffffff;
    font-weight: 600;
}

/* Cards & Containers */
QFrame.CardFrame {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 16px;
}

QFrame.SubCardFrame {
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 12px;
}

/* Section Headings */
QLabel.HeaderTitle {
    font-size: 18px;
    font-weight: 700;
    color: #0f172a;
}

QLabel.SectionTitle {
    font-size: 15px;
    font-weight: 600;
    color: #1e293b;
}

QLabel.SubText {
    font-size: 12px;
    color: #64748b;
}

/* Status Badges */
QLabel.BadgeValid {
    background-color: #dcfce7;
    color: #15803d;
    border: 1px solid #86efac;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeWarning {
    background-color: #fef3c7;
    color: #b45309;
    border: 1px solid #fcd34d;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeExpired {
    background-color: #fee2e2;
    color: #b91c1c;
    border: 1px solid #fca5a5;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

QLabel.BadgeInfo {
    background-color: #dbeafe;
    color: #1d4ed8;
    border: 1px solid #93c5fd;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 11px;
    font-weight: 600;
}

/* Primary and Action Buttons */
QPushButton {
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}

QPushButton:hover {
    background-color: #f1f5f9;
    border-color: #94a3b8;
}

QPushButton:pressed {
    background-color: #e2e8f0;
}

QPushButton:disabled {
    background-color: #f8fafc;
    color: #94a3b8;
    border-color: #e2e8f0;
}

QPushButton.PrimaryButton {
    background-color: #2563eb;
    color: #ffffff;
    border: 1px solid #1d4ed8;
    font-weight: 600;
}

QPushButton.PrimaryButton:hover {
    background-color: #1d4ed8;
}

QPushButton.SuccessButton {
    background-color: #059669;
    color: #ffffff;
    border: 1px solid #047857;
    font-weight: 600;
}

QPushButton.SuccessButton:hover {
    background-color: #047857;
}

QPushButton.DangerButton {
    background-color: #dc2626;
    color: #ffffff;
    border: 1px solid #b91c1c;
    font-weight: 600;
}

QPushButton.DangerButton:hover {
    background-color: #b91c1c;
}

/* Form Inputs */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit, QSpinBox {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    color: #0f172a;
    padding: 8px 12px;
    font-size: 13px;
    selection-background-color: #2563eb;
}

QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #2563eb;
    background-color: #ffffff;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

/* Tables */
QTableWidget {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    gridline-color: #f1f5f9;
    color: #0f172a;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QHeaderView::section {
    background-color: #f8fafc;
    color: #475569;
    font-weight: 600;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #e2e8f0;
    border-right: 1px solid #f1f5f9;
}

/* Status Bar */
QStatusBar {
    background-color: #ffffff;
    border-top: 1px solid #e2e8f0;
    color: #64748b;
    font-size: 12px;
}

/* ScrollBars */
QScrollBar:vertical {
    border: none;
    background-color: #f1f5f9;
    width: 8px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background-color: #cbd5e1;
    min-height: 20px;
    border-radius: 4px;
}

QScrollBar::handle:vertical:hover {
    background-color: #94a3b8;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

/* Tab Widget */
QTabWidget::pane {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    background-color: #ffffff;
    padding: 10px;
}

QTabBar::tab {
    background-color: #f1f5f9;
    border: 1px solid #e2e8f0;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 8px 16px;
    margin-right: 4px;
    color: #64748b;
}

QTabBar::tab:selected {
    background-color: #ffffff;
    color: #2563eb;
    border-bottom: 2px solid #2563eb;
    font-weight: 600;
}
"""
