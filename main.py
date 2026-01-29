"""
TurboSTL Credits + Stripe Backend (FastAPI)

What this service does:
- Verifies Supabase user sessions (JWT) using SUPABASE_ANON_KEY
- Provides /me and /charge endpoints used by TurboSTL Streamlit
- Handles Stripe webhooks to reset credits to 100 on successful renewal (invoice.paid)
- (Optional but recommended) Creates Stripe Checkout sessions tied to the logged-in user
  so you can reliably map Stripe customer/subscription -> Supabase user.

Deploy this as a separate DigitalOcean App Platform component (Python service).
"""

import os
import time
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import requests
import stripe
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from supabase import create_client

# -----------------------------
# Config
# -----------------------------
SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_ANON_KEY = os.environ["SUPABASE_ANON_KEY"]
SUPABASE_SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Optional: to create checkout sessions from this API
STRIPE_PRICE_ID = os.environ.get("STRIPE_PRICE_ID", "")  # e.g. price_123
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "")    # e.g. https://your-streamlit-app.com
CHECKOUT_SUCCESS_PATH = os.environ.get("CHECKOUT_SUCCESS_PATH", "/")  # where to send after payment
CHECKOUT_CANCEL_PATH = os.environ.get("CHECKOUT_CANCEL_PATH", "/")    # where to send if canceled

stripe.api_key = STRIPE_SECRET_KEY if STRIPE_SECRET_KEY else None

sb_admin = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = FastAPI(title="TurboSTL Credits API")


# -----------------------------
# Helpers
# -----------------------------
def _iso_from_epoch_seconds(sec: int) -> str:
    """Convert epoch seconds -> ISO 8601 string in UTC for timestamptz columns."""
    return datetime.fromtimestamp(int(sec), tz=timezone.utc).isoformat()

def _require_bearer_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    return auth.split(" ", 1)[1].strip()

def _get_user_email_from_supabase(access_token: str) -> str:
    """
    Validate the Supabase session JWT and return the user's email.
    This avoids storing SUPABASE_SERVICE_ROLE_KEY anywhere in the Streamlit app.
    """
    r = requests.get(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={"Authorization": f"Bearer {access_token}", "apikey": SUPABASE_ANON_KEY},
        timeout=15,
    )
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid session")
    data = r.json()
    email = data.get("email")
    if not email:
        raise HTTPException(status_code=401, detail="No email on session")
    return email.lower()

def _get_or_create_user_id(email: str) -> str:
    # Upsert user record (email unique)
    sb_admin.table("users").upsert({"email": email}, on_conflict="email").execute()
    row = sb_admin.table("users").select("id").eq("email", email).single().execute()
    return row.data["id"]

def _ensure_credits_row(user_id: str) -> None:
    sb_admin.table("credits").upsert({"user_id": user_id}, on_conflict="user_id").execute()

def _find_user_id_by_stripe_customer(customer_id: str) -> Optional[str]:
    try:
        row = (
            sb_admin.table("subscriptions")
            .select("user_id")
            .eq("stripe_customer_id", customer_id)
            .single()
            .execute()
        )
        return row.data["user_id"]
    except Exception:
        return None

def _upsert_subscription(user_id: str, customer_id: str, subscription: Dict[str, Any]) -> None:
    sb_admin.table("subscriptions").upsert(
        {
            "user_id": user_id,
            "stripe_customer_id": customer_id,
            "stripe_subscription_id": subscription.get("id"),
            "status": subscription.get("status", "unknown"),
            "current_period_start": _iso_from_epoch_seconds(subscription["current_period_start"])
            if subscription.get("current_period_start") else None,
            "current_period_end": _iso_from_epoch_seconds(subscription["current_period_end"])
            if subscription.get("current_period_end") else None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        on_conflict="user_id",
    ).execute()

def _set_credits_for_period(user_id: str, balance: int, period_start: int, period_end: int, ref: Optional[str]) -> None:
    sb_admin.table("credits").upsert(
        {
            "user_id": user_id,
            "balance": int(balance),
            "period_start": _iso_from_epoch_seconds(period_start) if period_start else None,
            "period_end": _iso_from_epoch_seconds(period_end) if period_end else None,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        },
        on_conflict="user_id",
    ).execute()

    sb_admin.table("credit_ledger").insert(
        {
            "user_id": user_id,
            "delta": int(balance),  # store refill amount as delta for clarity (e.g., +100)
            "reason": "monthly_reset",
            "ref": ref,
        }
    ).execute()


# -----------------------------
# Basic endpoints
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/me")
def me(request: Request):
    token = _require_bearer_token(request)
    email = _get_user_email_from_supabase(token)
    user_id = _get_or_create_user_id(email)
    _ensure_credits_row(user_id)

    credits = sb_admin.table("credits").select("balance,period_end").eq("user_id", user_id).single().execute().data
    return {
        "email": email,
        "balance": int(credits.get("balance", 0) or 0),
        "period_end": credits.get("period_end"),
    }

@app.post("/charge")
async def charge(request: Request):
    token = _require_bearer_token(request)
    body = await request.json()
    cost = int(body.get("cost", 0))
    ref = body.get("ref")

    if cost not in (1, 2):
        raise HTTPException(status_code=400, detail="Invalid cost (must be 1 or 2)")

    email = _get_user_email_from_supabase(token)
    user_id = _get_or_create_user_id(email)
    _ensure_credits_row(user_id)

    # Atomic decrement via RPC (recommended)
    res = sb_admin.rpc("charge_credits", {"p_user_id": user_id, "p_cost": cost, "p_ref": ref}).execute()
    if not res.data:
        # 402 is convenient to distinguish from normal errors
        raise HTTPException(status_code=402, detail="Insufficient credits")

    return {"new_balance": int(res.data[0]["new_balance"])}


# -----------------------------
# Optional: create checkout session tied to logged-in user
# -----------------------------
@app.post("/create-checkout-session")
async def create_checkout_session(request: Request):
    """
    Creates a Stripe Checkout session for the logged-in user and stores the resulting
    stripe_customer_id / stripe_subscription_id after checkout.session.completed webhook fires.

    Requires env:
    - STRIPE_SECRET_KEY
    - STRIPE_PRICE_ID
    - PUBLIC_APP_URL
    """
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID or not PUBLIC_APP_URL:
        raise HTTPException(status_code=500, detail="Stripe checkout is not configured on the server")

    token = _require_bearer_token(request)
    email = _get_user_email_from_supabase(token)
    user_id = _get_or_create_user_id(email)

    # Reuse/create a Stripe customer for this user
    # If you already stored stripe_customer_id, reuse it.
    sub_row = (
        sb_admin.table("subscriptions")
        .select("stripe_customer_id")
        .eq("user_id", user_id)
        .maybe_single()
        .execute()
    )
    existing_customer = None
    if sub_row and getattr(sub_row, "data", None):
        existing_customer = sub_row.data.get("stripe_customer_id")

    if existing_customer:
        customer_id = existing_customer
    else:
        customer = stripe.Customer.create(email=email, metadata={"supabase_user_id": user_id, "email": email})
        customer_id = customer["id"]
        # Save customer_id now; subscription id will be saved on webhook
        sb_admin.table("subscriptions").upsert(
            {
                "user_id": user_id,
                "stripe_customer_id": customer_id,
                "status": "incomplete",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
            on_conflict="user_id",
        ).execute()

    success_url = f"{PUBLIC_APP_URL.rstrip('/')}{CHECKOUT_SUCCESS_PATH}?checkout=success"
    cancel_url = f"{PUBLIC_APP_URL.rstrip('/')}{CHECKOUT_CANCEL_PATH}?checkout=cancel"

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=customer_id,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        allow_promotion_codes=True,
    )
    return {"url": session["url"]}


# -----------------------------
# Stripe webhook (credits reset)
# -----------------------------
@app.post("/stripe/webhook")
async def stripe_webhook(req: Request):
    """
    Recommended event handling:
    - checkout.session.completed: link subscription ID and mark status
    - customer.subscription.created/updated: keep period dates/status fresh
    - invoice.paid: refill credits to 100 for the new billing period
    """
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not configured")

    payload = await req.body()
    sig = req.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook signature error: {e}")

    etype = event.get("type")
    obj = event["data"]["object"]

    # 1) After checkout completes, store subscription id + status for the customer
    if etype == "checkout.session.completed":
        customer_id = obj.get("customer")
        sub_id = obj.get("subscription")
        if customer_id and sub_id:
            user_id = _find_user_id_by_stripe_customer(customer_id)
            if user_id:
                sub = stripe.Subscription.retrieve(sub_id)
                _upsert_subscription(user_id, customer_id, sub)

    # 2) Keep subscription status/period current
    if etype in ("customer.subscription.created", "customer.subscription.updated"):
        customer_id = obj.get("customer")
        if customer_id:
            user_id = _find_user_id_by_stripe_customer(customer_id)
            if user_id:
                _upsert_subscription(user_id, customer_id, obj)

    # 3) Refill credits on successful invoice payment
    if etype == "invoice.paid":
        customer_id = obj.get("customer")
        sub_id = obj.get("subscription")
        invoice_id = obj.get("id")
        if customer_id and sub_id:
            user_id = _find_user_id_by_stripe_customer(customer_id)
            if user_id:
                sub = stripe.Subscription.retrieve(sub_id)
                period_start = int(sub["current_period_start"])
                period_end = int(sub["current_period_end"])
                # Set credits to 100 for this paid period
                sb_admin.table("credits").upsert(
                    {
                        "user_id": user_id,
                        "balance": 100,
                        "period_start": _iso_from_epoch_seconds(period_start),
                        "period_end": _iso_from_epoch_seconds(period_end),
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                    on_conflict="user_id",
                ).execute()
                sb_admin.table("credit_ledger").insert(
                    {"user_id": user_id, "delta": 100, "reason": "monthly_reset", "ref": invoice_id}
                ).execute()

    return JSONResponse({"ok": True})
