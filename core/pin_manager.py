"""
Dhanyah Crypto Utility - Hardware Token PIN Management
Safe PIN verification, safe PIN changes (C_SetPIN), and lock counter safeguards.
"""

import logging
from typing import Dict, Optional, Tuple, Any

from core.constants import (
    TOKEN_PROFILES,
    PKCS11_ERRORS,
)

logger = logging.getLogger("DhanyahCrypto.PIN")


class PinResult:
    """Encapsulates the result of a PIN operation."""

    def __init__(
        self,
        success: bool,
        message: str,
        error_code: Optional[int] = None,
        retries_remaining: Optional[int] = None,
        is_locked: bool = False,
    ):
        self.success = success
        self.message = message
        self.error_code = error_code
        self.retries_remaining = retries_remaining
        self.is_locked = is_locked

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "error_code": self.error_code,
            "retries_remaining": self.retries_remaining,
            "is_locked": self.is_locked,
        }

    def __repr__(self) -> str:
        return f"<PinResult success={self.success} message='{self.message}'>"


class PinManager:
    """Manages token PIN verification and change operations."""

    def __init__(self, pkcs11_mgr=None):
        self.pkcs11_mgr = pkcs11_mgr
        # Simulation state
        self._sim_pin = "12345678"
        self._sim_retries = 15
        self._sim_locked = False

    def verify_pin(self, token_id: str, slot: int, pin: str, is_simulated: bool = False) -> PinResult:
        """
        Safely verifies the token PIN.
        Opens a session, performs C_Login(CKU_USER), and immediately calls C_Logout.
        """
        if not pin:
            return PinResult(False, "PIN cannot be empty.")

        # Simulation mode check
        if is_simulated or token_id == "SIMULATED":
            return self._verify_pin_simulated(pin)

        if not self.pkcs11_mgr:
            return PinResult(False, "PKCS#11 manager is not initialized.")

        # Auto-resolve active slot from hardware
        active_slots = self.pkcs11_mgr.get_slots_with_token(token_id)
        if active_slots and (slot is None or slot not in active_slots):
            slot = active_slots[0]

        import PyKCS11
        from PyKCS11 import PyKCS11Error, CKU_USER

        try:
            lib = self.pkcs11_mgr.get_pkcs11_lib(token_id)
            session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
            try:
                # Attempt C_Login
                session.login(pin, CKU_USER)
                # Success: logout immediately to free state
                session.logout()
                logger.info(f"PIN verified successfully on {token_id} slot {slot}")
                return PinResult(True, "Token PIN is correct and hardware is responsive.")

            except PyKCS11Error as pe:
                code = getattr(pe, "value", None)
                if code == 0x000000A0:  # CKR_PIN_INCORRECT
                    return PinResult(
                        False,
                        "Incorrect Token PIN entered! Please verify carefully.",
                        error_code=code,
                        retries_remaining=None,
                        is_locked=False,
                    )
                elif code == 0x000000A4:  # CKR_PIN_LOCKED
                    return PinResult(
                        False,
                        "TOKEN LOCKED / BLOCKED! The maximum PIN attempt limit was exceeded. Token administrator unlock required.",
                        error_code=code,
                        is_locked=True,
                    )
                elif code == 0x000000A2:  # CKR_PIN_LEN_RANGE
                    return PinResult(
                        False,
                        "PIN length is out of range. Indian tokens typically require 4-16 characters.",
                        error_code=code,
                    )
                elif code == 0x00000101:  # CKR_USER_ALREADY_LOGGED_IN
                    # Already logged in from previous process
                    try:
                        session.logout()
                    except Exception:
                        pass
                    return PinResult(True, "Token PIN verified (User was already authenticated).")
                else:
                    msg = self.pkcs11_mgr.map_pkcs11_error(code) if code else str(pe)
                    return PinResult(False, f"Verification failed: {msg}", error_code=code)
            finally:
                session.closeSession()

        except Exception as e:
            logger.error(f"Error during verify_pin: {e}")
            return PinResult(False, f"System error during PIN verification: {str(e)}")

    def change_pin(
        self,
        token_id: str,
        slot: int,
        old_pin: str,
        new_pin: str,
        confirm_pin: str,
        is_simulated: bool = False,
    ) -> PinResult:
        """
        Safely changes user PIN using C_Login and C_SetPIN.
        """
        if new_pin != confirm_pin:
            return PinResult(False, "New PIN and Confirm PIN do not match.")

        if len(new_pin) < 4 or len(new_pin) > 16:
            return PinResult(False, "New PIN length must be between 4 and 16 characters.")

        if old_pin == new_pin:
            return PinResult(False, "New PIN cannot be identical to the Old PIN.")

        if is_simulated or token_id == "SIMULATED":
            return self._change_pin_simulated(old_pin, new_pin)

        if not self.pkcs11_mgr:
            return PinResult(False, "PKCS#11 manager is not initialized.")

        # Auto-resolve active slot from hardware
        active_slots = self.pkcs11_mgr.get_slots_with_token(token_id)
        if active_slots and (slot is None or slot not in active_slots):
            slot = active_slots[0]

        import PyKCS11
        from PyKCS11 import PyKCS11Error, CKU_USER

        try:
            lib = self.pkcs11_mgr.get_pkcs11_lib(token_id)
            session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
            try:
                # 1. Login with old PIN
                session.login(old_pin, CKU_USER)

                # 2. Invoke C_SetPIN
                session.setPIN(old_pin, new_pin)

                # 3. Logout
                session.logout()

                logger.info(f"PIN changed successfully for {token_id} slot {slot}")
                return PinResult(True, "Token PIN changed successfully!")

            except PyKCS11Error as pe:
                code = getattr(pe, "value", None)
                if code == 0x000000A0:  # CKR_PIN_INCORRECT
                    return PinResult(
                        False,
                        "Old PIN is incorrect. Operation aborted.",
                        error_code=code,
                    )
                elif code == 0x000000A4:  # CKR_PIN_LOCKED
                    return PinResult(
                        False,
                        "Token is LOCKED! PIN cannot be changed.",
                        error_code=code,
                        is_locked=True,
                    )
                else:
                    msg = self.pkcs11_mgr.map_pkcs11_error(code) if code else str(pe)
                    return PinResult(False, f"PIN change failed: {msg}", error_code=code)
            finally:
                session.closeSession()

        except Exception as e:
            logger.error(f"Error during change_pin: {e}")
            return PinResult(False, f"System error during PIN change: {str(e)}")

    def _verify_pin_simulated(self, pin: str) -> PinResult:
        if self._sim_locked:
            return PinResult(False, "Simulated Token is LOCKED.", is_locked=True)

        if pin == self._sim_pin:
            self._sim_retries = 15
            return PinResult(True, "PIN verified successfully (Simulated Hardware Token).")
        else:
            self._sim_retries -= 1
            if self._sim_retries <= 0:
                self._sim_locked = True
                return PinResult(False, "Simulated Token is now LOCKED!", is_locked=True)
            return PinResult(
                False,
                f"Incorrect PIN! {self._sim_retries} attempts remaining before token lock.",
                retries_remaining=self._sim_retries,
            )

    def _change_pin_simulated(self, old_pin: str, new_pin: str) -> PinResult:
        if self._sim_locked:
            return PinResult(False, "Simulated Token is LOCKED.", is_locked=True)

        if old_pin != self._sim_pin:
            return PinResult(False, "Current Old PIN is incorrect.")

        self._sim_pin = new_pin
        return PinResult(True, "PIN updated successfully on Simulated Token.")
