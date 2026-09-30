"""
Dhanyah Crypto Utility - Windows Smart Card Subsystem & MiniDriver Registrar
Enables zero-install plug-and-play support across Windows, Adobe Acrobat,
Chrome, Edge, and browser web portals (MCA, GST, Income Tax, EPFO).
"""

import ctypes
import logging
import os
import shutil
import subprocess
import sys
import winreg
from typing import Dict, Tuple, Any, Optional

logger = logging.getLogger("DhanyahCrypto.Registrar")

SMARTCARD_REG_ROOTS = [
    r"SOFTWARE\Microsoft\Cryptography\Calais\SmartCards",
    r"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Calais\SmartCards",
]

CSP_REG_ROOTS = [
    r"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",
    r"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider",
]

CARD_DEFINITIONS = {
    "mtoken_blue": {
        "name": "Longmai mToken SmartCard",
        "label": "mToken Blue (CryptoID Classic)",
        "atr": bytes.fromhex("3b9f118131fe9f006a6d546f6b656e2d50000081900000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff0000ffffff00"),
        "crypto_provider": "Microsoft Base Smart Card Crypto Provider",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "minidriver_64": "mTokenMiniDrv.x64.dll",
        "minidriver_32": "mTokenMiniDrv.dll",
        "csp_name": "mToken CryptoID CSP",
        "csp_image": "basecsp.dll",
        "csp_type": 1,
    },
    "mtoken_purple": {
        "name": "Longmai mToken CryptoFIPS",
        "label": "mToken Purple (CryptoID FIPS F3)",
        "atr": bytes.fromhex("3b9f118131fe9f006a6d546f6b656e2d45000081900000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff0000ffffff00"),
        "crypto_provider": "Microsoft Base Smart Card Crypto Provider",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "minidriver_64": "mTokenMiniDrvF3.x64.dll",
        "minidriver_32": "mTokenMiniDrvF3.dll",
        "csp_name": "mToken CryptoID CSP",
        "csp_image": "basecsp.dll",
        "csp_type": 1,
    },
    "hyp2003": {
        "name": "HYP2003v2",
        "atr": bytes.fromhex("3b9f958131fe9f006646530500000071df000006000000"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffff000000ffffffffffffff00"),
        "crypto_provider": "HyperPKI HYP2003 CSP India v3.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "HyperPKI HYP2003 CSP India v3.0",
        "csp_image": r"C:\Windows\system32\eps2003csp11v2_s.dll",
        "csp_type": 1,
    },
    "proxkey": {
        "name": "WD_Ultimate Key Minidriver",
        "atr": bytes.fromhex("3b6d000057443641018693000000000000"),
        "atr_mask": bytes.fromhex("fffffffffffffffffffff00000000000"),
        "crypto_provider": "PROXKey CSP India V3.0",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "PROXKey CSP India V3.0",
        "csp_image": r"C:\Windows\system32\Watchdata\PROXKey CSP India V3.0\wdsafe3.dll",
        "csp_type": 1,
    },
    "innait": {
        "name": "InnaIT SmartCard",
        "atr": bytes.fromhex("3b8e8001504b035858585f4453435f4b45594c"),
        "atr_mask": bytes.fromhex("ffffffffffffffffffffffffffffffffff"),
        "crypto_provider": "InnaIT Cryptographic Provider CSP",
        "ksp": "Microsoft Smart Card Key Storage Provider",
        "csp_name": "InnaIT Cryptographic Provider CSP",
        "csp_image": r"C:\Windows\system32\InnaITCSP.dll",
        "csp_type": 1,
    },
}


class SmartCardRegistrar:
    """Manages Windows Smart Card subsystem registration and certificate propagation."""

    @staticmethod
    def is_admin() -> bool:
        """Check if current process has Administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def check_subsystem_health() -> Dict[str, Any]:
        """Inspects registry and service state for all 4 vendor tokens."""
        status = {
            "is_admin": SmartCardRegistrar.is_admin(),
            "cards": {},
            "services": {
                "CertPropSvc": False,
                "SCardSvr": False,
            },
        }

        # Check Calais SmartCard definitions
        for token_key, cfg in CARD_DEFINITIONS.items():
            card_name = cfg["name"]
            is_reg_64 = False
            is_reg_32 = False

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards\\{card_name}",
                ):
                    is_reg_64 = True
            except OSError:
                pass

            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    f"SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Calais\\SmartCards\\{card_name}",
                ):
                    is_reg_32 = True
            except OSError:
                pass

            status["cards"][token_key] = {
                "name": card_name,
                "registered": is_reg_64 or is_reg_32,
                "registered_64": is_reg_64,
                "registered_32": is_reg_32,
            }

        # Check Windows Services
        for svc_name in ["CertPropSvc", "SCardSvr"]:
            try:
                res = subprocess.run(
                    ["sc", "query", svc_name],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                if "RUNNING" in res.stdout:
                    status["services"][svc_name] = True
            except Exception:
                pass

        return status

    @staticmethod
    def pulse_windows_certificates() -> bool:
        """
        Triggers Windows Certificate Propagation Service to refresh all connected
        smart card tokens and publish their certificates into CurrentUser\My.
        """
        try:
            logger.info("Pulsing Windows Certificate Propagation Service (certutil -user -pulse)...")
            res = subprocess.run(
                ["certutil", "-user", "-pulse"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return res.returncode == 0
        except Exception as e:
            logger.warning(f"Failed to pulse certificates via certutil: {e}")
            return False

    @staticmethod
    def register_windows_subsystem(drivers_source_dir: Optional[str] = None) -> Tuple[bool, str]:
        """
        Registers all 4 Smart Card MiniDrivers, Calais SmartCard registry entries,
        and CSP providers into Windows so Adobe Acrobat and Browsers recognize tokens.
        """
        if not SmartCardRegistrar.is_admin():
            return False, "Administrator privileges are required to configure Windows Smart Card drivers."

        if not drivers_source_dir:
            if getattr(sys, "frozen", False):
                base_dir = os.path.dirname(sys.executable)
                candidates = [
                    os.path.join(base_dir, "drivers"),
                    os.path.join(base_dir, "_internal", "drivers"),
                ]
            else:
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                candidates = [os.path.join(base_dir, "drivers")]

            for c in candidates:
                if os.path.isdir(c):
                    drivers_source_dir = c
                    break

        if not drivers_source_dir or not os.path.isdir(drivers_source_dir):
            return False, f"Bundled drivers directory not found: {drivers_source_dir}"

        system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        syswow64 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "SysWOW64")
        has_wow64 = os.path.isdir(syswow64)

        def _safe_copy(src: str, dst: str):
            """Safely copy driver binary without failing if destination file is locked/in-use."""
            try:
                if not os.path.exists(dst):
                    shutil.copy2(src, dst)
                else:
                    try:
                        shutil.copy2(src, dst)
                    except PermissionError:
                        logger.debug(f"Destination {dst} in use; skipping overwrite.")
            except Exception as ex:
                logger.debug(f"Error copying {src} -> {dst}: {ex}")

        try:
            # 1. Copy MiniDriver & CSP DLLs
            logger.info(f"Deploying MiniDriver and CSP binaries from {drivers_source_dir}...")

            # mToken MiniDrivers (Both Blue & Purple F3)
            mtoken_src = os.path.join(drivers_source_dir, "mtoken")
            if os.path.isdir(mtoken_src):
                # Blue Classic
                m_x64 = os.path.join(mtoken_src, "mTokenMiniDrv.x64.dll")
                m_32 = os.path.join(mtoken_src, "mTokenMiniDrv.dll")
                p11_blue = os.path.join(mtoken_src, "cryptoida_pkcs11.dll")

                if os.path.isfile(m_x64):
                    _safe_copy(m_x64, os.path.join(system32, "mTokenMiniDrv.x64.dll"))
                if os.path.isfile(m_32):
                    _safe_copy(m_32, os.path.join(system32, "mTokenMiniDrv.dll"))
                    if has_wow64:
                        _safe_copy(m_32, os.path.join(syswow64, "mTokenMiniDrv.dll"))
                if os.path.isfile(p11_blue):
                    _safe_copy(p11_blue, os.path.join(system32, "cryptoida_pkcs11.dll"))
                    if has_wow64:
                        _safe_copy(p11_blue, os.path.join(syswow64, "cryptoida_pkcs11.dll"))

                # Purple FIPS F3
                mf3_x64 = os.path.join(mtoken_src, "mTokenMiniDrvF3.x64.dll")
                mf3_32 = os.path.join(mtoken_src, "mTokenMiniDrvF3.dll")
                p11_purple = os.path.join(mtoken_src, "cryptoida_pkcs11_f3.dll")

                if os.path.isfile(mf3_x64):
                    _safe_copy(mf3_x64, os.path.join(system32, "mTokenMiniDrvF3.x64.dll"))
                if os.path.isfile(mf3_32):
                    _safe_copy(mf3_32, os.path.join(system32, "mTokenMiniDrvF3.dll"))
                    if has_wow64:
                        _safe_copy(mf3_32, os.path.join(syswow64, "mTokenMiniDrvF3.dll"))
                if os.path.isfile(p11_purple):
                    _safe_copy(p11_purple, os.path.join(system32, "cryptoida_pkcs11_f3.dll"))
                    if has_wow64:
                        _safe_copy(p11_purple, os.path.join(syswow64, "cryptoida_pkcs11_f3.dll"))

            # HyperPKI CSP files
            hyp_src = os.path.join(drivers_source_dir, "hyp2003")
            if os.path.isdir(hyp_src):
                for f in ["eps2003csp11v2_s.dll", "eps2003csp11v2.sig", "eps2003csp11v2.dll"]:
                    fp = os.path.join(hyp_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(system32, f))
                        if has_wow64:
                            _safe_copy(fp, os.path.join(syswow64, f))

            # ProxKey files
            prox_src = os.path.join(drivers_source_dir, "proxkey")
            if os.path.isdir(prox_src):
                prox_dest = os.path.join(system32, "Watchdata", "PROXKey CSP India V3.0")
                os.makedirs(prox_dest, exist_ok=True)
                for f in os.listdir(prox_src):
                    fp = os.path.join(prox_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(prox_dest, f))

            # InnaIT files
            innait_src = os.path.join(drivers_source_dir, "innait")
            if os.path.isdir(innait_src):
                for f in os.listdir(innait_src):
                    fp = os.path.join(innait_src, f)
                    if os.path.isfile(fp):
                        _safe_copy(fp, os.path.join(system32, f))
                        if has_wow64:
                            _safe_copy(fp, os.path.join(syswow64, f))

            # 2. Register Calais SmartCards in Registry
            for root_path in SMARTCARD_REG_ROOTS:
                for token_key, cfg in CARD_DEFINITIONS.items():
                    card_name = cfg["name"]
                    key_path = f"{root_path}\\{card_name}"
                    try:
                        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                            winreg.SetValueEx(k, "ATR", 0, winreg.REG_BINARY, cfg["atr"])
                            winreg.SetValueEx(k, "ATRMask", 0, winreg.REG_BINARY, cfg["atr_mask"])
                            winreg.SetValueEx(k, "Crypto Provider", 0, winreg.REG_SZ, cfg["crypto_provider"])
                            if "ksp" in cfg:
                                winreg.SetValueEx(k, "Smart Card Key Storage Provider", 0, winreg.REG_SZ, cfg["ksp"])
                            if "minidriver_64" in cfg:
                                mini_dll = cfg["minidriver_32"] if "WOW6432Node" in root_path else cfg["minidriver_64"]
                                winreg.SetValueEx(k, "80000001", 0, winreg.REG_SZ, mini_dll)
                    except Exception as e:
                        logger.warning(f"Error registering Calais SmartCard key {key_path}: {e}")

            # 3. Register CSP Providers
            for root_path in CSP_REG_ROOTS:
                for token_key, cfg in CARD_DEFINITIONS.items():
                    if "csp_name" in cfg:
                        csp_name = cfg["csp_name"]
                        key_path = f"{root_path}\\{csp_name}"
                        try:
                            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
                                winreg.SetValueEx(k, "Image Path", 0, winreg.REG_SZ, cfg["csp_image"])
                                winreg.SetValueEx(k, "Type", 0, winreg.REG_DWORD, cfg.get("csp_type", 1))
                                winreg.SetValueEx(k, "SigInFile", 0, winreg.REG_DWORD, 0)
                        except Exception as e:
                            logger.warning(f"Error registering CSP provider key {key_path}: {e}")

            # 4. Start / Enable Services
            for svc in ["SCardSvr", "CertPropSvc"]:
                try:
                    subprocess.run(["sc", "config", svc, "start=", "auto"], capture_output=True, timeout=2)
                    subprocess.run(["sc", "start", svc], capture_output=True, timeout=2)
                except Exception:
                    pass

            # 5. Pulse Certificate Propagation
            SmartCardRegistrar.pulse_windows_certificates()

            logger.info("Successfully registered Windows Smart Card subsystem for all 4 tokens.")
            return True, "Windows Smart Card subsystem and MiniDrivers registered successfully for all 4 tokens."

        except Exception as e:
            logger.exception("Failed to register Windows Smart Card subsystem")
            return False, f"Registration error: {e}"
