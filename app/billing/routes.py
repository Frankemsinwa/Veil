"""FastAPI routing endpoints for Veil Billing, Pricing Plans, and Paystack Integration."""
import logging
from typing import Optional, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from app.licensing.models import LicenseTier, FeatureFlag
from app.licensing.manager import license_manager
from app.billing.paystack import paystack_client

logger = logging.getLogger(__name__)

billing_router = APIRouter(prefix="/api/billing", tags=["billing"])


class CheckoutRequest(BaseModel):
    tier: LicenseTier = Field(default=LicenseTier.PRO, description="Target plan tier")
    email: str = Field(..., description="Developer or company contact email")
    currency: str = Field(default="NGN", description="Currency: 'NGN' or 'USD'")
    callback_url: Optional[str] = Field(None, description="Optional redirect after payment")


class VerifyRequest(BaseModel):
    reference: str = Field(..., description="Paystack transaction reference")


class ActivateKeyRequest(BaseModel):
    license_key: str = Field(..., description="Signed Veil license key string")


# Pricing table amount definitions in lowest denomination (Kobo for NGN, Cents for USD)
PLAN_PRICING = {
    LicenseTier.PRO: {
        "NGN": 30000 * 100,  # 30,000 NGN in Kobo = 3,000,000 kobo
        "USD": 20 * 100,     # $20.00 USD in Cents = 2,000 cents
    },
    LicenseTier.ENTERPRISE: {
        "NGN": 90000 * 100,  # 90,000 NGN in Kobo
        "USD": 60 * 100,     # $60.00 USD in Cents
    },
}


@billing_router.get("/plans")
async def get_plans():
    """Returns all available commercial plans, feature entitlements, and active tier."""
    plans = license_manager.get_all_plans()
    active_license = license_manager.get_active_license()

    return {
        "status": "success",
        "active_tier": active_license.tier.value,
        "is_expired": active_license.is_expired(),
        "expires_at": active_license.expires_at,
        "plans": [p.model_dump() for p in plans],
    }


@billing_router.get("/status")
async def get_billing_status():
    """Returns the active license status, customer email, and feature flags."""
    active_license = license_manager.get_active_license()
    return {
        "status": "success",
        "license_id": active_license.license_id,
        "tier": active_license.tier.value,
        "customer_email": active_license.customer_email,
        "is_expired": active_license.is_expired(),
        "issued_at": active_license.issued_at,
        "expires_at": active_license.expires_at,
        "max_clients": active_license.max_clients,
        "features": [f.value for f in active_license.features],
    }


@billing_router.post("/checkout")
async def create_checkout(req: CheckoutRequest):
    """Initializes a Paystack transaction and returns the hosted checkout URL."""
    if req.tier == LicenseTier.FREE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The Community/Solo tier is free and does not require checkout."
        )

    currency = req.currency.upper()
    if currency not in ("NGN", "USD"):
        currency = "NGN"

    tier_pricing = PLAN_PRICING.get(req.tier, {})
    amount = tier_pricing.get(currency)
    if not amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported currency '{currency}' for plan '{req.tier.value}'"
        )

    metadata = {
        "tier": req.tier.value,
        "email": req.email,
        "currency": currency,
        "product": "Veil Privacy Gateway",
    }

    success, result = await paystack_client.initialize_transaction(
        email=req.email,
        amount=amount,
        currency=currency,
        callback_url=req.callback_url,
        metadata=metadata,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=result.get("error", "Failed to initialize payment transaction with Paystack.")
        )

    return {
        "status": "success",
        "authorization_url": result["authorization_url"],
        "access_code": result["access_code"],
        "reference": result["reference"],
        "is_sandbox": result.get("is_sandbox", False),
        "amount_formatted": f"₦{amount // 100:,}" if currency == "NGN" else f"${amount / 100:.2f}",
        "currency": currency,
    }


@billing_router.post("/verify")
async def verify_payment(req: VerifyRequest):
    """
    Verifies a Paystack payment reference.
    Upon verification, issues and activates a signed Veil license key automatically.
    """
    success, txn_data = await paystack_client.verify_transaction(req.reference)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=txn_data.get("error", "Transaction could not be verified.")
        )

    # Extract customer email and tier from metadata
    meta = txn_data.get("metadata", {})
    tier_str = meta.get("tier", "PRO")
    customer_email = txn_data.get("customer", {}).get("email") or meta.get("email", "customer@veil.local")

    try:
        tier_enum = LicenseTier(tier_str)
    except ValueError:
        tier_enum = LicenseTier.PRO

    # Issue cryptographically signed 30-day license
    key_str, payload = license_manager.issue_license(
        tier=tier_enum,
        customer_email=customer_email,
        duration_days=30,
    )

    # Automatically activate locally
    activated, act_msg, _ = license_manager.activate_license(key_str)
    if not activated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"License issued but activation failed: {act_msg}"
        )

    return {
        "status": "success",
        "message": f"Payment verified! Upgraded to Veil {tier_enum.value} tier.",
        "license_key": key_str,
        "tier": tier_enum.value,
        "customer_email": customer_email,
        "expires_at": payload.expires_at,
    }


@billing_router.post("/activate")
async def activate_license_key(req: ActivateKeyRequest):
    """Activates an existing or offline license key manually."""
    valid, message, payload = license_manager.activate_license(req.license_key)
    if not valid or not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return {
        "status": "success",
        "message": message,
        "tier": payload.tier.value,
        "license_id": payload.license_id,
        "customer_email": payload.customer_email,
        "expires_at": payload.expires_at,
        "max_clients": payload.max_clients,
    }


@billing_router.get("/sandbox-checkout", response_class=HTMLResponse)
async def sandbox_checkout_page(ref: str):
    """Interactive local sandbox checkout page for development, demos, and testing."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Veil Payment Sandbox (Paystack Demo)</title>
      <style>
        body {{
          background-color: #0b0f19;
          color: #e2e8f0;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
        }}
        .card {{
          background: #111827;
          border: 1px solid #1f2937;
          border-radius: 12px;
          padding: 32px;
          max-width: 440px;
          width: 100%;
          text-align: center;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .badge {{
          background: #065f46;
          color: #34d399;
          font-size: 11px;
          font-weight: 700;
          text-transform: uppercase;
          padding: 4px 10px;
          border-radius: 20px;
          display: inline-block;
          margin-bottom: 12px;
        }}
        h2 {{ margin-top: 0; color: #f9fafb; }}
        p {{ color: #9ca3af; font-size: 14px; line-height: 1.5; }}
        .btn {{
          background: #0ea5e9;
          color: #ffffff;
          border: none;
          border-radius: 8px;
          padding: 12px 24px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          width: 100%;
          margin-top: 20px;
          transition: background 0.2s;
        }}
        .btn:hover {{ background: #0284c7; }}
        .ref-box {{
          background: #1f2937;
          padding: 8px;
          border-radius: 6px;
          font-family: monospace;
          color: #38bdf8;
          font-size: 13px;
          margin: 16px 0;
        }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="badge">Paystack Local Test Sandbox</div>
        <h2>Complete Veil Pro Upgrade</h2>
        <p>This is Veil's local payment simulation. In live production, this redirects directly to Paystack's secure international card checkout.</p>
        <div class="ref-box">Ref: {ref}</div>
        <button class="btn" id="confirmBtn" onclick="confirmPayment()">Authorize Test Payment</button>
        <div id="statusMsg" style="margin-top: 15px; font-size: 13px; font-weight: bold;"></div>
      </div>
      <script>
        async function confirmPayment() {{
          const btn = document.getElementById("confirmBtn");
          const msg = document.getElementById("statusMsg");
          btn.disabled = true;
          btn.innerText = "Verifying with Veil Gateway...";
          try {{
            const res = await fetch("/api/billing/verify", {{
              method: "POST",
              headers: {{ "Content-Type": "application/json" }},
              body: JSON.stringify({{ reference: "{ref}" }})
            }});
            const data = await res.json();
            if (res.ok) {{
              msg.style.color = "#34d399";
              msg.innerText = "✓ " + data.message + " Redirecting back...";
              setTimeout(() => {{ window.location.href = "/"; }}, 1200);
            }} else {{
              msg.style.color = "#ef4444";
              msg.innerText = "Error: " + (data.detail || "Payment verification failed");
              btn.disabled = false;
              btn.innerText = "Retry Payment";
            }}
          }} catch (err) {{
            msg.style.color = "#ef4444";
            msg.innerText = "Network error: " + err.message;
            btn.disabled = false;
            btn.innerText = "Retry Payment";
          }}
        }}
      </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@billing_router.post("/webhook")
async def paystack_webhook(request: Request):
    """Paystack webhook listener for asynchronous charge events."""
    signature = request.headers.get("x-paystack-signature", "")
    payload_bytes = await request.body()

    if paystack_client.is_configured:
        if not paystack_client.verify_webhook_signature(payload_bytes, signature):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Paystack webhook signature."
            )

    try:
        event_data = json.loads(payload_bytes.decode("utf-8"))
        event_type = event_data.get("event")
        data = event_data.get("data", {})

        if event_type == "charge.success":
            reference = data.get("reference")
            meta = data.get("metadata", {})
            customer_email = data.get("customer", {}).get("email") or meta.get("email")
            tier_str = meta.get("tier", "PRO")

            logger.info(f"Received Paystack charge.success webhook for {reference} ({customer_email})")
            if reference and customer_email:
                tier_enum = LicenseTier.PRO if tier_str == "PRO" else LicenseTier.ENTERPRISE
                key_str, _ = license_manager.issue_license(tier_enum, customer_email)
                license_manager.activate_license(key_str)

        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error processing Paystack webhook: {e}")
        return {"status": "error", "message": str(e)}
