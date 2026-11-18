"""
Main Streamlit UI Entrypoint — Enterprise AP Invoice Automation Platform (P11-2).

Run locally per CLAUDE.md §14:
    streamlit run src/ui/app.py --server.port 8501

All backend interactions flow exclusively through ``src/ui/api_client.py`` (CLAUDE.md §4.2 & §12).
"""

import os
from typing import Any

from src.ui.api_client import (
    DEFAULT_API_BASE_URL,
    APIClientError,
    APInvoiceAPIClient,
    validate_api_base_url,
)
from src.ui.audit_viewer import render_audit_trail_viewer
from src.ui.exception_queue import render_exception_queue
from src.ui.ingestion_dashboard import render_ingestion_dashboard, sanitize_display_text
from src.ui.review_workbench import render_review_workbench
from src.ui.revision_screen import render_revision_comparison

DEFAULT_DEMO_PERSONAS: tuple[str, ...] = (
    "sarah.clerk",
    "michael.manager",
    "dave.admin",
)

PAGE_INGESTION: str = "Ingestion Dashboard (/)"
PAGE_WORKBENCH: str = "Review Workbench (/workbench)"
PAGE_EXCEPTIONS: str = "Human Exception Queue (/exceptions)"
PAGE_REVISION: str = "Revision Comparison (/revision)"
PAGE_AUDIT: str = "Audit Trail Viewer (/audit)"

NAVIGATION_PAGES: tuple[str, ...] = (
    PAGE_INGESTION,
    PAGE_WORKBENCH,
    PAGE_EXCEPTIONS,
    PAGE_REVISION,
    PAGE_AUDIT,
)


def _get_streamlit(st_module: Any | None) -> Any:
    if st_module is not None:
        return st_module
    import streamlit as st

    return st


def build_ui_api_client(*, access_token: str | None = None) -> APInvoiceAPIClient:
    """Construct a validated ``APInvoiceAPIClient`` from ``AP_API_BASE_URL`` env config."""
    raw_url = os.environ.get("AP_API_BASE_URL", DEFAULT_API_BASE_URL)
    safe_url = validate_api_base_url(raw_url)
    return APInvoiceAPIClient(base_url=safe_url, access_token=access_token)


def _clear_session_batch_state(session_state: dict[str, Any]) -> None:
    """Purge cached batch & workbench rows on sign-out or identity switch (SEC-193, CWE-200/384)."""
    for key in (
        "batch_items",
        "poll_cycles",
        "selected_workbench_invoice_id",
        "workbench_invoice",
        "workbench_last_revalidation",
        "exception_assignments",
        "revision_original_id",
        "revision_incoming_id",
        "revision_pair",
        "revision_decisions",
        "audit_invoice_id",
        "audit_trail",
    ):
        session_state.pop(key, None)


def render_app(
    *,
    api_client: APInvoiceAPIClient | None = None,
    st_module: Any | None = None,
) -> None:
    """Render the Enterprise AP Invoice Automation Streamlit application."""
    st = _get_streamlit(st_module)
    st.set_page_config(
        page_title="Enterprise AP Invoice Automation",
        layout="wide",
    )

    owns_client = api_client is None
    saved_token: str | None = st.session_state.get("access_token")
    client = api_client if api_client is not None else build_ui_api_client(access_token=saved_token)
    if saved_token and not client.is_authenticated:
        client.set_access_token(saved_token)

    try:
        # --- Sidebar: Identity, Backend Readiness & Page Navigation ---
        st.sidebar.header("Enterprise AP Platform")

        # 1. Backend Health Badge (public /health liveness probe)
        try:
            health_data = client.health()
            health_status = sanitize_display_text(
                str(health_data.get("status", "healthy")), max_length=32
            )
            st.sidebar.caption(f"Backend API: {health_status}")
        except APIClientError:
            st.sidebar.warning("Backend API unreachable — check FastAPI server status.")

        # 2. Authentication (Demo Persona or Masked Bearer JWT)
        persona_names = list(DEFAULT_DEMO_PERSONAS)
        try:
            personas_resp = client.list_demo_personas()
            if personas_resp.personas:
                persona_names = [p.username for p in personas_resp.personas]
        except APIClientError:
            pass

        selected_persona = st.sidebar.selectbox(
            "Demo Persona",
            options=persona_names,
            index=0,
        )
        if st.sidebar.button("Sign In as Demo Persona"):
            try:
                prev_email = st.session_state.get("user_email")
                tok = client.issue_demo_token(selected_persona)
                if prev_email and prev_email != tok.email:
                    _clear_session_batch_state(st.session_state)
                st.session_state["access_token"] = tok.access_token
                st.session_state["user_email"] = tok.email
                st.session_state["user_name"] = tok.name
                st.session_state["user_roles"] = [tok.role]
                st.sidebar.success(
                    f"Signed in as {sanitize_display_text(tok.name, max_length=80)} ({tok.role})"
                )
            except APIClientError as exc:
                st.sidebar.error(sanitize_display_text(str(exc), max_length=180))

        manual_token = st.sidebar.text_input(
            "Or paste Entra ID Bearer Token",
            value="",
            type="password",
        )
        if manual_token.strip() and st.sidebar.button("Apply Bearer Token"):
            try:
                prev_email = st.session_state.get("user_email")
                client.set_access_token(manual_token.strip())
                me = client.get_me()
                if prev_email and prev_email != me.email:
                    _clear_session_batch_state(st.session_state)
                st.session_state["access_token"] = manual_token.strip()
                st.session_state["user_email"] = me.email
                st.session_state["user_name"] = me.name
                st.session_state["user_roles"] = list(me.roles)
                st.sidebar.success(
                    f"Authenticated as {sanitize_display_text(me.name, max_length=80)}"
                )
            except (ValueError, APIClientError) as exc:
                client.set_access_token(None)
                st.sidebar.error(sanitize_display_text(str(exc), max_length=180))

        active_roles: list[str] | None = st.session_state.get("user_roles")
        if st.session_state.get("user_email"):
            user_email = sanitize_display_text(str(st.session_state["user_email"]), max_length=100)
            roles_str = ", ".join(active_roles or [])
            st.sidebar.caption(f"Signed in: {user_email} [{roles_str}]")
            if st.sidebar.button("Sign Out"):
                client.set_access_token(None)
                for key in ("access_token", "user_email", "user_name", "user_roles"):
                    st.session_state.pop(key, None)
                _clear_session_batch_state(st.session_state)
                active_roles = None

        st.sidebar.divider()
        selected_page = st.sidebar.radio("Navigation", options=list(NAVIGATION_PAGES), index=0)

        # --- Main Page Router ---
        effective_roles = active_roles if active_roles is not None else []
        if selected_page == PAGE_INGESTION:
            render_ingestion_dashboard(
                client,
                st_module=st,
                user_roles=effective_roles,
            )
        elif selected_page == PAGE_WORKBENCH:
            render_review_workbench(
                client,
                st_module=st,
                user_roles=effective_roles,
            )
        elif selected_page == PAGE_EXCEPTIONS:
            render_exception_queue(
                client,
                st_module=st,
                user_roles=effective_roles,
            )
        elif selected_page == PAGE_REVISION:
            render_revision_comparison(
                client,
                st_module=st,
                user_roles=effective_roles,
            )
        elif selected_page == PAGE_AUDIT:
            render_audit_trail_viewer(
                client,
                st_module=st,
                user_roles=effective_roles,
            )
        else:
            st.title(selected_page)
            st.info("Unknown navigation route selected.")
    finally:
        if owns_client:
            client.close()


if __name__ == "__main__":
    render_app()
