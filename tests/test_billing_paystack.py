"""Integration tests for Paystack billing, pricing plans, and checkout endpoints."""
import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.billing.paystack import paystack_client
from app.licensing.manager import license_manager
from app.licensing.models import LicenseTier


@pytest.mark.asyncio
async def test_get_billing_plans():
    """Verify GET /api/billing/plans returns pricing in NGN and USD."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/billing/plans")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert len(data["plans"]) == 3
        
        # Check Pro tier pricing
        pro_plan = next(p for p in data["plans"] if p["tier"] == "PRO")
        assert pro_plan["price_usd_monthly"] == 20.0
        assert pro_plan["price_ngn_monthly"] == 30000


@pytest.mark.asyncio
async def test_get_billing_status_default():
    """Verify GET /api/billing/status returns default Free tier initially."""
    license_manager.clear_license()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/billing/status")
        assert res.status_code == 200
        data = res.json()
        assert data["tier"] == "FREE"
        assert data["is_expired"] is False


@pytest.mark.asyncio
async def test_checkout_initialization_ngn_and_usd():
    """Verify POST /api/billing/checkout creates sandbox Paystack transaction."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # NGN checkout
        res_ngn = await ac.post("/api/billing/checkout", json={
            "tier": "PRO",
            "email": "customer@lagos.ng",
            "currency": "NGN"
        })
        assert res_ngn.status_code == 200
        data_ngn = res_ngn.json()
        assert "authorization_url" in data_ngn
        assert data_ngn["currency"] == "NGN"
        assert "₦30,000" in data_ngn["amount_formatted"]

        # USD checkout
        res_usd = await ac.post("/api/billing/checkout", json={
            "tier": "PRO",
            "email": "customer@global.com",
            "currency": "USD"
        })
        assert res_usd.status_code == 200
        data_usd = res_usd.json()
        assert data_usd["currency"] == "USD"
        assert "$20.00" in data_usd["amount_formatted"]


@pytest.mark.asyncio
async def test_checkout_and_verify_flow():
    """Verify complete end-to-end flow: initialize checkout -> verify payment -> license unlocked."""
    license_manager.clear_license()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Initialize checkout
        init_res = await ac.post("/api/billing/checkout", json={
            "tier": "PRO",
            "email": "dev@fintech.ng",
            "currency": "NGN"
        })
        assert init_res.status_code == 200
        ref = init_res.json()["reference"]

        # 2. Verify payment
        verify_res = await ac.post("/api/billing/verify", json={"reference": ref})
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["tier"] == "PRO"
        assert verify_data["license_key"].startswith("VL-PRO-")

        # 3. Check status is now PRO
        status_res = await ac.get("/api/billing/status")
        assert status_res.json()["tier"] == "PRO"
        assert license_manager.get_active_license().tier == LicenseTier.PRO

    license_manager.clear_license()


@pytest.mark.asyncio
async def test_manual_license_key_activation():
    """Verify POST /api/billing/activate with signed key."""
    license_manager.clear_license()
    # Issue a signed key
    key_str, _ = license_manager.issue_license(LicenseTier.PRO, "offline@client.com")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Activate with valid key
        res = await ac.post("/api/billing/activate", json={"license_key": key_str})
        assert res.status_code == 200
        assert res.json()["tier"] == "PRO"

        # Attempt to activate with invalid key
        bad_res = await ac.post("/api/billing/activate", json={"license_key": "VL-PRO-fake.badsig"})
        assert bad_res.status_code == 400

    license_manager.clear_license()
