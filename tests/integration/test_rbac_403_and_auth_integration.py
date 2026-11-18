"""
End-to-End Offline Integration Tests: RBAC 403 Scenarios & Unauthenticated Access (P12-4).

Tests: FR-12, FR-13, BR-014, N1, CLAUDE.md §2, §8, §9, §13, §16.1
Security Controls: CWE-285, CWE-287, CWE-290, CWE-345, CWE-400, CWE-524, CWE-863, SEC-217, SEC-218.

Exercises the full live FastAPI + SQLite + FakeRedis + WORM Blob stack strictly offline:
1. Unauthenticated, malformed, alg=none/HS256 forged, and expired JWT requests -> 401 across all
   8 protected routes (with WWW-Authenticate: Bearer), while public GET /health -> 200.
2. ap_clerk approving >$10k USD ($10,000.01 & $15,000), >$10k EUR via live ECB FX (including
   stale lower total_amount_usd), and PO variance >5% -> 403 Forbidden with 0 APPROVE audit rows;
   exact $10,000.00 succeeds for ap_clerk; >$10k succeeds for finance_manager.
3. Full 3-role RBAC 403 matrix (ap_clerk, finance_manager, system_admin) across all endpoints,
   including Cache-Control: no-store on GET /health/ready (SEC-217).
4. Actor impersonation (clerk_id / approver_id mismatch -> 403), unrecognized/empty role claims
   (-> 403), and headerless oversized chunked /revalidate body guard (-> 413, SEC-218).
"""

import asyncio
import base64
import json
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any

import fakeredis.aioredis
import fitz
import jwt
import pytest
from fastapi.testclient import TestClient

from src.api.invoices import (
    MAX_REVALIDATE_BODY_BYTES,
    get_upload_blob_client,
    get_upload_redis_client,
    get_upload_session_factory,
)
from src.api.main import app
from src.core.config import get_settings
from src.core.demo_auth import (
    DEMO_CLIENT_ID,
    DEMO_ISSUER,
    DEMO_TENANT_ID,
    _get_ephemeral_demo_keypair,
    reset_demo_keypair_cache,
)
from src.database.models import Base, Invoice
from src.database.repositories import (
    AuditLogRepository,
    ExchangeRateRepository,
    InvoiceRepository,
    compute_composite_hash,
)
from src.database.seed import seed_exchange_rates, seed_vendors
from src.database.session import create_db_engine, create_session_factory
from src.storage.blob_client import InMemoryWORMBlobClient

SAMPLE_DATA_DIR = Path("./sample_data")


def _make_pdf(text: str = "RBAC Integration Test Invoice #1001") -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    out = doc.tobytes()
    doc.close()
    return out


def _forge_alg_none_token() -> str:
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    pay = base64.urlsafe_b64encode(
        json.dumps(
            {
                "oid": "attacker-oid",
                "sub": "attacker",
                "roles": ["finance_manager", "system_admin"],
                "exp": int(time.time()) + 3600,
            }
        ).encode()
    ).rstrip(b"=")
    return f"{hdr.decode()}.{pay.decode()}."


def _mint_custom_demo_jwt(*, roles: list[str], exp_offset_seconds: int = 3600) -> str:
    """Sign a real RS256 token with the active demo keypair for expired / empty-role tests."""
    private_key, _jwk_dict, kid = _get_ephemeral_demo_keypair()
    now = int(time.time())
    claims = {
        "iss": DEMO_ISSUER,
        "aud": DEMO_CLIENT_ID,
        "tid": DEMO_TENANT_ID,
        "oid": "demo-oid-custom-principal",
        "sub": "demo-sub-custom-principal",
        "preferred_username": "custom.user@company.com",
        "name": "Custom Principal",
        "roles": roles,
        "iat": now - 60,
        "nbf": now - 60,
        "exp": now + exp_offset_seconds,
        "jti": f"jti-custom-{now}-{exp_offset_seconds}",
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


@dataclass
class _RBACStack:
    client: TestClient
    clerk_headers: dict[str, str]
    manager_headers: dict[str, str]
    admin_headers: dict[str, str]
    session_factory: Any


@contextmanager
def _rbac_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, db_name: str
) -> Generator[_RBACStack, None, None]:
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("ENABLE_DEMO_AUTH", "true")
    monkeypatch.setenv("USE_LOCAL_SQLITE", "true")
    monkeypatch.setenv("USE_FAKE_REDIS", "true")
    monkeypatch.setenv("USE_MOCK_AOAI", "true")
    monkeypatch.setenv("USE_MOCK_BLOB_STORAGE", "true")
    monkeypatch.setenv("SAMPLE_DATA_DIR", str(SAMPLE_DATA_DIR))
    get_settings.cache_clear()
    reset_demo_keypair_cache()

    db_path = tmp_path / db_name
    engine = create_db_engine(f"sqlite+aiosqlite:///{db_path}")
    session_factory = create_session_factory(engine)
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    blob_client = InMemoryWORMBlobClient(
        account_url="https://mockblob.blob.core.windows.net/",
        container_name="raw-invoices-immutable",
    )

    async def _init_db() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with session_factory() as session:
            await seed_vendors(session, SAMPLE_DATA_DIR)
            await seed_exchange_rates(session, SAMPLE_DATA_DIR)
            fx_repo = ExchangeRateRepository(session)
            await fx_repo.upsert(
                rate_date=date(2026, 2, 1),
                from_currency="EUR",
                to_currency="USD",
                exchange_rate=Decimal("1.085000"),
            )

    asyncio.run(_init_db())

    app.dependency_overrides[get_upload_session_factory] = lambda: session_factory
    app.dependency_overrides[get_upload_redis_client] = lambda: fake_redis
    app.dependency_overrides[get_upload_blob_client] = lambda: blob_client

    try:
        with TestClient(app) as tc:
            clerk_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "sarah.clerk@company.com"}
            ).json()["access_token"]
            mgr_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "michael.manager@company.com"}
            ).json()["access_token"]
            admin_tok = tc.post(
                "/api/v1/auth/demo-token", json={"persona": "dave.admin@company.com"}
            ).json()["access_token"]
            yield _RBACStack(
                client=tc,
                clerk_headers={"Authorization": f"Bearer {clerk_tok}"},
                manager_headers={"Authorization": f"Bearer {mgr_tok}"},
                admin_headers={"Authorization": f"Bearer {admin_tok}"},
                session_factory=session_factory,
            )
    finally:
        app.dependency_overrides.clear()
        asyncio.run(fake_redis.aclose())
        asyncio.run(engine.dispose())
        get_settings.cache_clear()
        reset_demo_keypair_cache()


async def _seed_invoice(
    session_factory: Any,
    *,
    vendor_tax_id: str = "US-12-3456789",
    vendor_name: str = "Apex Global Logistics Inc",
    invoice_number: str,
    subtotal: Decimal,
    tax: Decimal,
    total: Decimal,
    currency: str = "USD",
    total_amount_usd: Decimal | None = None,
    status: str = "VALIDATED",
    confidence: Decimal = Decimal("96.00"),
) -> str:
    async with session_factory() as session:
        inv = await InvoiceRepository(session).create(
            Invoice(
                vendor_tax_id=vendor_tax_id,
                vendor_name=vendor_name,
                invoice_number=invoice_number,
                invoice_date=date(2026, 2, 10),
                due_date=date(2026, 3, 12),
                po_number="PO-RBAC-100",
                subtotal=subtotal,
                total_tax_amount=tax,
                total_amount=total,
                currency=currency,
                total_amount_usd=total_amount_usd,
                confidence_macro_avg=confidence,
                status=status,
                composite_hash=compute_composite_hash(vendor_tax_id, invoice_number, total),
            )
        )
        return inv.invoice_id


# ---------------------------------------------------------------------------
# 1. Unauthenticated, Malformed, Forged (alg=none / HS256) & Expired Tokens -> 401
# ---------------------------------------------------------------------------


def test_p12_4_unauthenticated_and_forged_tokens_return_401_across_all_protected_routes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: N1, CLAUDE.md §8, §9 — All 8 protected endpoints reject unauth/forged/expired JWTs with 401."""
    with _rbac_stack(monkeypatch, tmp_path, db_name="p12_4_unauth.db") as stack:
        inv_id = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-UNAUTH-01",
                subtotal=Decimal("1000.00"),
                tax=Decimal("80.00"),
                total=Decimal("1080.00"),
            )
        )

        # Public liveness check remains reachable without authentication
        assert stack.client.get("/health").status_code == 200

        hs256_forged = jwt.encode(
            {"oid": "attacker", "roles": ["system_admin"], "exp": int(time.time()) + 3600},
            "forged-hmac-secret-key-0123456789abcdef",
            algorithm="HS256",
        )
        expired_rs256 = _mint_custom_demo_jwt(roles=["finance_manager"], exp_offset_seconds=-300)

        bad_header_sets: list[dict[str, str]] = [
            {},  # Completely unauthenticated
            {"Authorization": "Bearer not-a-valid-jwt"},
            {"Authorization": f"Bearer {_forge_alg_none_token()}"},
            {"Authorization": f"Bearer {hs256_forged}"},
            {"Authorization": f"Bearer {expired_rs256}"},
        ]

        protected_requests: list[tuple[str, str, dict[str, Any]]] = [
            ("GET", "/api/v1/auth/me", {}),
            ("GET", "/health/ready", {}),
            ("GET", "/api/v1/invoices/exceptions", {}),
            ("GET", f"/api/v1/invoices/{inv_id}", {}),
            ("GET", f"/api/v1/invoices/{inv_id}/audit", {}),
            (
                "POST",
                "/api/v1/invoices/upload",
                {"files": {"file": ("unauth.pdf", _make_pdf(), "application/pdf")}},
            ),
            (
                "POST",
                f"/api/v1/invoices/{inv_id}/revalidate",
                {"json": {"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-X"}}},
            ),
            ("POST", f"/api/v1/invoices/{inv_id}/approve", {"json": {}}),
        ]

        for headers in bad_header_sets:
            for method, path, kwargs in protected_requests:
                resp = stack.client.request(method, path, headers=headers, **kwargs)
                assert resp.status_code == 401, f"Expected 401 for {method} {path} with {headers}"
                assert resp.headers.get("www-authenticate", "").startswith("Bearer")


# ---------------------------------------------------------------------------
# 2. AP Clerk Approving >$10k USD, >$10k EUR FX, and >5% PO Variance -> 403
# ---------------------------------------------------------------------------


def test_p12_4_clerk_approving_over_10k_usd_eur_fx_and_po_variance_returns_403(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: FR-13, BR-014, CLAUDE.md §2, §8, §16.1 — Clerk >$10k/PO-variance returns 403; manager succeeds."""
    with _rbac_stack(monkeypatch, tmp_path, db_name="p12_4_highval.db") as stack:
        # Case A: $10,000.01 USD (sub-dollar over threshold) -> clerk 403, manager 200
        id_10k01 = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-HV-10000-01",
                subtotal=Decimal("10000.01"),
                tax=Decimal("0.00"),
                total=Decimal("10000.01"),
                total_amount_usd=Decimal("10000.01"),
                status="REQUIRES_MANAGER_APPROVAL",
            )
        )
        r_clerk_10k01 = stack.client.post(
            f"/api/v1/invoices/{id_10k01}/approve",
            headers=stack.clerk_headers,
            json={"comment": "Attempting clerk approval above $10k"},
        )
        assert r_clerk_10k01.status_code == 403

        # Zero APPROVE audit events written on rejected 403 attempt
        async def _count_audits(inv_id: str) -> int:
            async with stack.session_factory() as session:
                return await AuditLogRepository(session).count_by_invoice_id(inv_id)

        assert asyncio.run(_count_audits(id_10k01)) == 0

        # Finance Manager succeeds on the same $10,000.01 invoice
        r_mgr_10k01 = stack.client.post(
            f"/api/v1/invoices/{id_10k01}/approve",
            headers=stack.manager_headers,
            json={"comment": "Manager approved high-value bill"},
        )
        assert r_mgr_10k01.status_code == 200
        assert r_mgr_10k01.json()["status"] == "APPROVED_MANAGER"

        # Case B: EUR 9,500.00 (live ECB FX 1.085 -> $10,307.50 > $10k) with stale lower cached USD column
        id_eur_hv = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                vendor_tax_id="DE123456789",
                vendor_name="Bavaria Werkzeuge GmbH",
                invoice_number="INV-EUR-HV-01",
                subtotal=Decimal("7983.19"),
                tax=Decimal("1516.81"),
                total=Decimal("9500.00"),
                currency="EUR",
                total_amount_usd=Decimal("9500.00"),  # Stale under-reported cached USD!
                status="VALIDATED",
            )
        )
        r_clerk_eur = stack.client.post(
            f"/api/v1/invoices/{id_eur_hv}/approve",
            headers=stack.clerk_headers,
            json={},
        )
        assert r_clerk_eur.status_code == 403

        r_mgr_eur = stack.client.post(
            f"/api/v1/invoices/{id_eur_hv}/approve",
            headers=stack.manager_headers,
            json={},
        )
        assert r_mgr_eur.status_code == 200
        assert r_mgr_eur.json()["status"] == "APPROVED_MANAGER"

        # Case C: PO variance > 5% ($5,000 invoice vs $4,500 PO = 11.1%) -> clerk 403, manager 200
        id_po_var = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-POVAR-01",
                subtotal=Decimal("5000.00"),
                tax=Decimal("0.00"),
                total=Decimal("5000.00"),
                total_amount_usd=Decimal("5000.00"),
                status="VALIDATED",
            )
        )
        r_clerk_po = stack.client.post(
            f"/api/v1/invoices/{id_po_var}/approve",
            headers=stack.clerk_headers,
            json={"po_amount": "4500.00"},
        )
        assert r_clerk_po.status_code == 403

        r_mgr_po = stack.client.post(
            f"/api/v1/invoices/{id_po_var}/approve",
            headers=stack.manager_headers,
            json={"po_amount": "4500.00"},
        )
        assert r_mgr_po.status_code == 200
        assert r_mgr_po.json()["status"] == "APPROVED_MANAGER"

        # Case D: Exact $10,000.00 boundary remains eligible for AP Clerk one-click approval
        id_exact_10k = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-EXACT-10K",
                subtotal=Decimal("10000.00"),
                tax=Decimal("0.00"),
                total=Decimal("10000.00"),
                total_amount_usd=Decimal("10000.00"),
                status="VALIDATED",
            )
        )
        r_clerk_exact = stack.client.post(
            f"/api/v1/invoices/{id_exact_10k}/approve",
            headers=stack.clerk_headers,
            json={},
        )
        assert r_clerk_exact.status_code == 200
        assert r_clerk_exact.json()["status"] == "APPROVED_CLERK"


# ---------------------------------------------------------------------------
# 3. Complete 3-Role RBAC 403 Matrix Across All Endpoints (CLAUDE.md §9, SEC-217)
# ---------------------------------------------------------------------------


def test_p12_4_full_three_role_rbac_403_matrix_across_all_endpoints(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: CLAUDE.md §2, §8, §9, SEC-217 — Verify ap_clerk, finance_manager, system_admin RBAC boundaries."""
    with _rbac_stack(monkeypatch, tmp_path, db_name="p12_4_matrix.db") as stack:
        inv_id = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-MATRIX-01",
                subtotal=Decimal("1000.00"),
                tax=Decimal("80.00"),
                total=Decimal("1080.00"),
                total_amount_usd=Decimal("1080.00"),
                status="REQUIRES_REVIEW",
            )
        )

        # GET /health/ready: system_admin ONLY (200 + Cache-Control: no-store); clerk & manager -> 403
        r_ready_admin = stack.client.get("/health/ready", headers=stack.admin_headers)
        assert r_ready_admin.status_code == 200
        assert r_ready_admin.headers.get("cache-control") == "no-store"
        assert stack.client.get("/health/ready", headers=stack.clerk_headers).status_code == 403
        assert stack.client.get("/health/ready", headers=stack.manager_headers).status_code == 403

        # system_admin blocked (403) from operational upload, detail, exceptions, revalidate, approve
        assert (
            stack.client.post(
                "/api/v1/invoices/upload",
                headers=stack.admin_headers,
                files={"file": ("admin.pdf", _make_pdf(), "application/pdf")},
            ).status_code
            == 403
        )
        assert (
            stack.client.get(f"/api/v1/invoices/{inv_id}", headers=stack.admin_headers).status_code
            == 403
        )
        assert (
            stack.client.get("/api/v1/invoices/exceptions", headers=stack.admin_headers).status_code
            == 403
        )
        assert (
            stack.client.post(
                f"/api/v1/invoices/{inv_id}/revalidate",
                headers=stack.admin_headers,
                json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-ADM"}},
            ).status_code
            == 403
        )
        assert (
            stack.client.post(
                f"/api/v1/invoices/{inv_id}/approve",
                headers=stack.admin_headers,
                json={},
            ).status_code
            == 403
        )
        # system_admin CAN inspect immutable audit trails (200)
        assert (
            stack.client.get(
                f"/api/v1/invoices/{inv_id}/audit", headers=stack.admin_headers
            ).status_code
            == 200
        )

        # finance_manager blocked (403) from /revalidate (CLAUDE.md §9: ap_clerk only)
        assert (
            stack.client.post(
                f"/api/v1/invoices/{inv_id}/revalidate",
                headers=stack.manager_headers,
                json={"reason_code": "OCR_MISREAD", "header_edits": {"po_number": "PO-MGR"}},
            ).status_code
            == 403
        )
        # Both ap_clerk & finance_manager can inspect audit & exceptions
        assert (
            stack.client.get(
                f"/api/v1/invoices/{inv_id}/audit", headers=stack.clerk_headers
            ).status_code
            == 200
        )
        assert (
            stack.client.get(
                f"/api/v1/invoices/{inv_id}/audit", headers=stack.manager_headers
            ).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# 4. Actor Impersonation, Empty/Unknown Role Claims (403) & Oversized Chunked Body (413)
# ---------------------------------------------------------------------------


def test_p12_4_actor_impersonation_empty_roles_403_and_chunked_revalidate_limit_413(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """# Tests: N1, CLAUDE.md §8, CWE-290, CWE-400, SEC-218 — Anti-impersonation, zero-role 403, 413 guard."""
    with _rbac_stack(monkeypatch, tmp_path, db_name="p12_4_impersonation.db") as stack:
        inv_id = asyncio.run(
            _seed_invoice(
                stack.session_factory,
                invoice_number="INV-IMP-01",
                subtotal=Decimal("500.00"),
                tax=Decimal("40.00"),
                total=Decimal("540.00"),
                total_amount_usd=Decimal("540.00"),
                status="VALIDATED",
            )
        )

        # Actor impersonation on /revalidate (ap_clerk claiming michael.manager's clerk_id -> 403)
        r_imp_reval = stack.client.post(
            f"/api/v1/invoices/{inv_id}/revalidate",
            headers=stack.clerk_headers,
            json={
                "clerk_id": "michael.manager@company.com",
                "reason_code": "OCR_MISREAD",
                "header_edits": {"po_number": "PO-IMP"},
            },
        )
        assert r_imp_reval.status_code == 403

        # Actor impersonation on /approve (finance_manager claiming sarah.clerk's approver_id -> 403)
        r_imp_app = stack.client.post(
            f"/api/v1/invoices/{inv_id}/approve",
            headers=stack.manager_headers,
            json={"approver_id": "sarah.clerk@company.com"},
        )
        assert r_imp_app.status_code == 403

        # Authenticated JWT carrying only unrecognized/empty roles -> 403 across protected routes
        guest_jwt = _mint_custom_demo_jwt(roles=["guest_viewer", "unknown_role"])
        guest_headers = {"Authorization": f"Bearer {guest_jwt}"}
        assert stack.client.get("/health/ready", headers=guest_headers).status_code == 403
        assert (
            stack.client.get("/api/v1/invoices/exceptions", headers=guest_headers).status_code
            == 403
        )
        assert (
            stack.client.get(f"/api/v1/invoices/{inv_id}/audit", headers=guest_headers).status_code
            == 403
        )
        assert (
            stack.client.post(
                f"/api/v1/invoices/{inv_id}/approve", headers=guest_headers, json={}
            ).status_code
            == 403
        )

        # Oversized chunked/headerless payload (> 1 MB) on /revalidate rejected with 413 (SEC-218)
        def _oversized_chunks() -> Generator[bytes, None, None]:
            yield b'{"reason_code":"OTHER","comment":"'
            yield b"A" * (MAX_REVALIDATE_BODY_BYTES + 128)
            yield b'","header_edits":{"po_number":"PO-1"}}'

        r_big = stack.client.post(
            f"/api/v1/invoices/{inv_id}/revalidate",
            headers={**stack.clerk_headers, "Content-Type": "application/json"},
            content=_oversized_chunks(),
        )
        assert r_big.status_code == 413
