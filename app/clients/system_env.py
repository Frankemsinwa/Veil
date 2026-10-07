"""Global Windows User Environment variable adapter with WM_SETTINGCHANGE broadcast."""
import os
import sys
import ctypes
from typing import Optional, Dict, Any

from app.clients.base import BaseClientAdapter
from app.clients.models import ClientInfo, ClientStatus, ClientType, MutationResult

# Windows API constants for environment broadcast
HWND_BROADCAST = 0xFFFF
WM_SETTINGCHANGE = 0x001A
SMTO_ABORTIFHUNG = 0x0002


class SystemEnvAdapter(BaseClientAdapter):
    """Sets user-level OPENAI_BASE_URL environment variable to route scripts/terminals through Veil."""

    ENV_VARS = ["OPENAI_BASE_URL", "OPENAI_API_BASE"]

    def __init__(self, mock_env: Optional[Dict[str, str]] = None):
        super().__init__(
            client_id="system_env",
            name="Global Shell & Scripts",
            client_type=ClientType.SYSTEM_ENV,
            icon="terminal",
            description="System-wide environment variables for LangChain, AutoGPT, and CLI scripts"
        )
        # Allows unit tests to test registry logic in isolation
        self._mock_env = mock_env

    def _broadcast_change(self):
        """Notifies Windows explorer and open consoles that environment variables have changed."""
        if sys.platform == "win32" and self._mock_env is None:
            try:
                result = ctypes.c_long()
                ctypes.windll.user32.SendMessageTimeoutW(
                    HWND_BROADCAST,
                    WM_SETTINGCHANGE,
                    0,
                    "Environment",
                    SMTO_ABORTIFHUNG,
                    1500,
                    ctypes.byref(result)
                )
            except Exception:
                pass

    def _get_registry_value(self, var_name: str) -> Optional[str]:
        if self._mock_env is not None:
            return self._mock_env.get(var_name)

        if sys.platform == "win32":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, var_name)
                    return str(val)
            except Exception:
                return None
        return os.environ.get(var_name)

    def _set_registry_value(self, var_name: str, value: str):
        if self._mock_env is not None:
            self._mock_env[var_name] = value
            return

        if sys.platform == "win32":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, var_name, 0, winreg.REG_SZ, value)
            except Exception as e:
                raise RuntimeError(f"Could not set Windows Registry HKCU\\Environment: {e}")
        os.environ[var_name] = value

    def _delete_registry_value(self, var_name: str):
        if self._mock_env is not None:
            self._mock_env.pop(var_name, None)
            return

        if sys.platform == "win32":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, var_name)
            except FileNotFoundError:
                pass
            except Exception as e:
                raise RuntimeError(f"Could not delete Windows Registry HKCU\\Environment value: {e}")
        os.environ.pop(var_name, None)

    def detect(self) -> bool:
        # System environment is always available on host
        return True

    def get_status(self) -> ClientInfo:
        current_url = self._get_registry_value("OPENAI_BASE_URL") or self._get_registry_value("OPENAI_API_BASE")
        is_connected = bool(current_url and "127.0.0.1" in current_url)

        return ClientInfo(
            id=self.client_id,
            name=self.name,
            client_type=self.client_type,
            status=ClientStatus.CONNECTED if is_connected else ClientStatus.DETECTED,
            icon=self.icon,
            description=self.description,
            config_path="HKCU\\Environment (Windows Registry)" if sys.platform == "win32" else "User Environment",
            has_backup=False,
            current_base_url=current_url,
            details={"env_vars": self.ENV_VARS}
        )

    def connect(self, gateway_url: str = "http://127.0.0.1:8080/v1") -> MutationResult:
        previous_url = self._get_registry_value("OPENAI_BASE_URL")
        try:
            for var in self.ENV_VARS:
                self._set_registry_value(var, gateway_url)

            self._broadcast_change()

            return MutationResult(
                success=True,
                message=f"Global environment successfully configured with OPENAI_BASE_URL={gateway_url}.",
                client_id=self.client_id,
                previous_url=previous_url,
                new_url=gateway_url
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to set system environment variables: {e}",
                client_id=self.client_id
            )

    def disconnect(self) -> MutationResult:
        try:
            for var in self.ENV_VARS:
                self._delete_registry_value(var)

            self._broadcast_change()

            return MutationResult(
                success=True,
                message="Removed Veil proxy from global environment variables.",
                client_id=self.client_id
            )
        except Exception as e:
            return MutationResult(
                success=False,
                message=f"Failed to clear system environment variables: {e}",
                client_id=self.client_id
            )
