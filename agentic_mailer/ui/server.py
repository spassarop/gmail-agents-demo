from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from testing_shared.telemetry import ensure_tracing

from ..logging_setup import configure_logging, get_logger
from ..session_store import SessionStore
from ..orchestrator import Orchestrator
from ..gmail_client import AuthRequired

logger = get_logger(__name__)


class SecurityHeadersMiddleware:
    """Basic security headers (defense-in-depth for the demo UI)."""

    def __init__(self, app: FastAPI):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                headers = dict(message.get("headers") or [])
                # Add/override security headers
                def _set(k: str, v: str):
                    headers[k.encode()] = v.encode()

                _set("x-content-type-options", "nosniff")
                _set("x-frame-options", "DENY")
                _set("referrer-policy", "no-referrer")
                _set("permissions-policy", "geolocation=(), microphone=(), camera=()")
                # CSP: no inline scripts; static files only
                _set(
                    "content-security-policy",
                    "default-src 'self'; "
                    "script-src 'self'; "
                    "style-src 'self'; "
                    "img-src 'self' data:; "
                    "connect-src 'self' ws: wss:; "
                    "frame-ancestors 'none'; "
                    "base-uri 'self'; "
                    "form-action 'self'",
                )

                message["headers"] = [(k, v) for k, v in headers.items()]
            await send(message)

        await self.app(scope, receive, send_wrapper)


def create_app(mode: str = "vulnerable") -> FastAPI:
    configure_logging()
    ensure_tracing(service_name=f"gmail-agents-demo-{mode}")

    app = FastAPI(title="Agentic ASI01 Demo", version="1.0.0")
    app.add_middleware(SecurityHeadersMiddleware)

    base_dir = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=str(base_dir / "templates"))

    app.mount("/static", StaticFiles(directory=str(base_dir / "static")), name="static")

    store = SessionStore()
    orchestrator = Orchestrator()

    SESSION_COOKIE = "asi01_session"

    # ------------------------------------------------------------------
    # Gmail OAuth endpoints
    # ------------------------------------------------------------------

    @app.get("/auth/start")
    async def auth_start(request: Request):
        """Generate the Google OAuth URL and redirect the user's browser to it."""
        redirect_uri = str(request.base_url).rstrip("/") + "/auth/callback"
        try:
            auth_url = orchestrator.gmail.prepare_auth_url(redirect_uri)
        except Exception as exc:
            return HTMLResponse(
                f"<h2>Cannot start auth: {exc}</h2>"
                "<p>Check that <code>secrets/credentials.json</code> exists.</p>",
                status_code=500,
            )
        return RedirectResponse(auth_url)

    @app.get("/auth/callback")
    async def auth_callback(request: Request, code: str = "", error: str = ""):
        """Handle the Google OAuth redirect, save the token, and return to the app."""
        if error:
            return HTMLResponse(
                f"<h2>Google authorization denied</h2><p>{error}</p>"
                "<p><a href='/'>Back to the app</a></p>",
                status_code=400,
            )
        if not code:
            return HTMLResponse(
                "<h2>Missing authorization code</h2>",
                status_code=400,
            )
        try:
            orchestrator.gmail.exchange_code(code)
        except Exception as exc:
            logger.exception("OAuth code exchange failed")
            return HTMLResponse(
                f"<h2>Authorization failed</h2><p>{exc}</p>"
                "<p><a href='/'>Back to the app</a></p>",
                status_code=500,
            )
        # Reload the original tab and close this one.
        return HTMLResponse(
            "<html><body><script>"
            "if(window.opener){window.opener.location.reload();window.close();}"
            "else{window.location.href='/';}"
            "</script><p>Authorized — closing this tab…</p></body></html>"
        )

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        # Create or reuse a session cookie
        session_id = request.cookies.get(SESSION_COOKIE)
        session = store.get_or_create(session_id)
        response = templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "mode": mode,
                "session_id": session.session_id,
            },
        )
        if not session_id:
            response.set_cookie(
                SESSION_COOKIE,
                session.session_id,
                httponly=True,
                samesite="lax",
                secure=False,  # local demo
            )
        return response

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket):
        await ws.accept()

        # Find session id from cookie in WS headers
        cookies = ws.headers.get("cookie", "")
        session_id = None
        for part in cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k == SESSION_COOKIE:
                    session_id = v
                    break
        session = store.get_or_create(session_id)

        logger.info("WS connect session=%s mode=%s", session.session_id, mode)

        async def send_auth_required() -> None:
            await ws.send_text(json.dumps({
                "type": "auth_required",
                "auth_url": "/auth/start",
                "reason": "Gmail authorization required. Click to sign in with Google.",
            }))

        # Notify the client immediately if credentials are missing or expired.
        if orchestrator.gmail.needs_auth():
            await send_auth_required()

        try:
            while True:
                raw = await ws.receive_text()
                try:
                    msg = json.loads(raw)
                except Exception:
                    msg = {"type": "user_message", "text": raw}

                if msg.get("type") != "user_message":
                    await ws.send_text(json.dumps({"type": "error", "error": "Unsupported message type"}))
                    continue

                text = str(msg.get("text", "") or "").strip()
                if not text:
                    continue

                try:
                    resp = orchestrator.handle_chat(session, text)
                except AuthRequired:
                    await send_auth_required()
                    continue

                await ws.send_text(
                    json.dumps(
                        {
                            "type": "assistant_message",
                            "assistant_text": resp.assistant_text,
                            "trace": [t.model_dump() for t in resp.trace],
                            "pending_action_id": resp.pending_action_id,
                            "pending_action_summary": resp.pending_action_summary,
                        }
                    )
                )
        except WebSocketDisconnect:
            logger.info("WS disconnect session=%s", session.session_id)
        except AuthRequired:
            try:
                await send_auth_required()
            except Exception:
                pass
        except Exception as e:
            logger.exception("WS error: %s", e)
            try:
                await ws.send_text(json.dumps({"type": "error", "error": str(e)}))
            except Exception:
                pass

    return app
