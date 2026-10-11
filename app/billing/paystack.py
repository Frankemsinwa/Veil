"""Paystack International & Local Payment Gateway Adapter."""
import hashlib
import hmac
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

PAYSTACK_BASE_URL = "https://api.paystack.co"


class PaystackClient:
    """Client for initializing and verifying Paystack payments."""

    def __init__(self, secret_key: Optional[str] = None, public_key: Optional[str] = None):
        self.secret_key = secret_key or os.environ.get("PAYSTACK_SECRET_KEY")
        self.public_key = public_key or os.environ.get("PAYSTACK_PUBLIC_KEY")
        # In-memory sandbox cache for mock transactions during development/testing
        self._mock_transactions: Dict[str, Dict[str, Any]] = {}

    @property
    def is_configured(self) -> bool:
        """Returns True if a real Paystack secret key is configured."""
        return bool(self.secret_key and not self.secret_key.startswith("mock_"))

    async def initialize_transaction(
        self,
        email: str,
        amount: int,
        currency: str = "NGN",
        callback_url: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Initializes a payment transaction on Paystack.
        Amount must be in the lowest currency unit (e.g., Kobo for NGN: 30000 NGN = 3000000 kobo; Cents for USD: $20 = 2000 cents).
        """
        reference = f"VEIL-{uuid.uuid4().hex[:12].upper()}"
        meta = metadata or {}
        meta["reference"] = reference

        if not self.is_configured:
            # Sandbox / Simulated checkout for local testing & demos
            logger.info(f"Paystack secret key not configured; using local simulated checkout for reference: {reference}")
            txn_record = {
                "status": "success",
                "reference": reference,
                "amount": amount,
                "currency": currency.upper(),
                "customer": {"email": email},
                "metadata": meta,
            }
            self._mock_transactions[reference] = txn_record
            self._save_sandbox_transaction(reference, txn_record)

            # Simulated hosted checkout redirect URL
            auth_url = f"http://{settings.HOST}:{settings.PORT}/api/billing/sandbox-checkout?ref={reference}"
            return True, {
                "authorization_url": auth_url,
                "access_code": f"mock_acc_{reference}",
                "reference": reference,
                "is_sandbox": True,
            }

        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "email": email,
            "amount": amount,
            "currency": currency.upper(),
            "reference": reference,
            "metadata": meta,
        }
        if callback_url:
            payload["callback_url"] = callback_url

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    f"{PAYSTACK_BASE_URL}/transaction/initialize",
                    json=payload,
                    headers=headers,
                )
                data = res.json()
                if res.status_code == 200 and data.get("status"):
                    return True, {
                        "authorization_url": data["data"]["authorization_url"],
                        "access_code": data["data"]["access_code"],
                        "reference": data["data"]["reference"],
                        "is_sandbox": False,
                    }
                else:
                    msg = data.get("message", "Payment initialization failed")
                    logger.error(f"Paystack initialize error: {msg}")
                    return False, {"error": msg}
        except Exception as e:
            logger.error(f"Failed to communicate with Paystack API: {e}")
            return False, {"error": str(e)}

    def _get_sandbox_file(self) -> Path:
        p = settings.DATA_DIR / "sandbox_transactions.json"
        return p

    def _save_sandbox_transaction(self, ref: str, data: Dict[str, Any]) -> None:
        try:
            settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
            sf = self._get_sandbox_file()
            current = {}
            if sf.exists():
                try:
                    current = json.loads(sf.read_text(encoding="utf-8"))
                except Exception:
                    current = {}
            current[ref] = data
            sf.write_text(json.dumps(current, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not persist sandbox transaction {ref}: {e}")

    def _load_sandbox_transaction(self, ref: str) -> Optional[Dict[str, Any]]:
        sf = self._get_sandbox_file()
        if sf.exists():
            try:
                current = json.loads(sf.read_text(encoding="utf-8"))
                return current.get(ref)
            except Exception:
                return None
        return None

    async def verify_transaction(self, reference: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Verifies a transaction via Paystack API or mock sandbox.
        Returns (success: bool, transaction_data: dict).
        """
        # Check mock sandbox first (in-memory or on disk)
        if reference in self._mock_transactions:
            return True, self._mock_transactions[reference]

        disk_txn = self._load_sandbox_transaction(reference)
        if disk_txn:
            self._mock_transactions[reference] = disk_txn
            return True, disk_txn

        if not self.is_configured:
            return False, {"error": "Paystack secret key not configured and reference not found in sandbox"}

        headers = {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.get(
                    f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
                    headers=headers,
                )
                data = res.json()
                if res.status_code == 200 and data.get("status"):
                    txn_data = data.get("data", {})
                    if txn_data.get("status") == "success":
                        return True, txn_data
                    else:
                        return False, {
                            "error": f"Transaction status is {txn_data.get('status')}",
                            "data": txn_data,
                        }
                else:
                    return False, {"error": data.get("message", "Verification failed")}
        except Exception as e:
            logger.error(f"Paystack verification request error: {e}")
            return False, {"error": str(e)}

    def verify_webhook_signature(self, payload_bytes: bytes, signature_header: str) -> bool:
        """
        Validates the HMAC-SHA512 signature on incoming Paystack webhook requests.
        Header: X-Paystack-Signature
        """
        if not self.secret_key or not signature_header:
            return False
        computed = hmac.new(self.secret_key.encode("utf-8"), payload_bytes, hashlib.sha512).hexdigest()
        return hmac.compare_digest(computed, signature_header)


# Global singleton
paystack_client = PaystackClient()
