"""Windows WinINet System Proxy Controller.

Manages system-level HTTP/HTTPS proxy configuration via the Windows Registry
and WinINet API notifications for instant live activation without reboots.
"""
from __future__ import annotations

import atexit
import ctypes
import logging
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger("veil.proxy.wininet")

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


class WindowsProxyManager:
    """Manages Windows CurrentUser Internet Proxy settings."""

    def __init__(self):
        self._original_state: Optional[Dict[str, Any]] = None
        self._hook_registered = False

    def _notify_wininet(self) -> bool:
        """Notifies WinINet to immediately apply updated proxy settings."""
        if sys.platform != "win32":
            return False

        try:
            r1 = ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            r2 = ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            return bool(r1 and r2)
        except Exception as e:
            logger.warning("Failed to notify WinINet via InternetSetOptionW: %s", e)
            return False

    def get_status(self) -> Dict[str, Any]:
        """Returns current Windows system proxy status."""
        if sys.platform != "win32":
            return {"enabled": False, "server": None, "override": None, "platform_supported": False}

        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ) as key:
                try:
                    proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                except FileNotFoundError:
                    proxy_enable = 0

                try:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                except FileNotFoundError:
                    proxy_server = None

                try:
                    proxy_override, _ = winreg.QueryValueEx(key, "ProxyOverride")
                except FileNotFoundError:
                    proxy_override = None

                return {
                    "enabled": bool(proxy_enable),
                    "server": proxy_server,
                    "override": proxy_override,
                    "platform_supported": True,
                }
        except Exception as e:
            logger.error("Error reading Windows proxy registry: %s", e)
            return {"enabled": False, "server": None, "override": None, "platform_supported": True, "error": str(e)}

    def enable_proxy(
        self,
        server: str = "127.0.0.1:8888",
        override: str = "<local>;localhost;127.0.0.1;127.*",
    ) -> bool:
        """Enables Windows system proxy pointing to Veil."""
        if sys.platform != "win32":
            logger.info("Windows proxy manager skipped on non-Windows OS.")
            return False

        import winreg

        current = self.get_status()
        if self._original_state is None:
            self._original_state = {
                "enabled": current.get("enabled", False),
                "server": current.get("server"),
                "override": current.get("override"),
            }

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, override)

            self._notify_wininet()
            self._ensure_cleanup_hook()
            logger.info("Windows System Proxy enabled: %s (Bypass: %s)", server, override)
            return True
        except Exception as e:
            logger.exception("Failed to write Windows proxy settings: %s", e)
            return False

    def disable_proxy(self) -> bool:
        """Disables Windows system proxy."""
        if sys.platform != "win32":
            return False

        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

            self._notify_wininet()
            logger.info("Windows System Proxy disabled.")
            return True
        except Exception as e:
            logger.exception("Failed to disable Windows proxy settings: %s", e)
            return False

    def restore_original(self) -> bool:
        """Restores proxy settings that were present before Veil was enabled."""
        if sys.platform != "win32" or self._original_state is None:
            return self.disable_proxy()

        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(
                    key,
                    "ProxyEnable",
                    0,
                    winreg.REG_DWORD,
                    1 if self._original_state.get("enabled") else 0,
                )
                if self._original_state.get("server"):
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, self._original_state["server"])
                if self._original_state.get("override"):
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self._original_state["override"])

            self._notify_wininet()
            logger.info("Restored original Windows System Proxy state.")
            return True
        except Exception as e:
            logger.exception("Failed to restore original Windows proxy settings: %s", e)
            return False

    def _ensure_cleanup_hook(self):
        """Ensures that proxy is cleanly reverted on process exit."""
        if not self._hook_registered:
            atexit.register(self.disable_proxy)
            self._hook_registered = True


proxy_manager = WindowsProxyManager()
