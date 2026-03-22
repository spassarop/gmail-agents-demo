from __future__ import annotations

import logging
from typing import Optional

from testinguy_shared.telemetry import traced

from ..session_store import PendingAction, SessionState

logger = logging.getLogger(__name__)


class HITLManager:
    """Human-in-the-loop confirmation manager.

    Stores pending actions in the user's session.
    """

    def create_pending(self, session: SessionState, kind: str, summary: str, payload: dict) -> PendingAction:
        with traced(
            "security.hitl.create_pending",
            attributes={
                "app.mode": "patched",
                "hitl.kind": kind,
                "hitl.pending_count_before": len(session.pending_actions),
            },
        ) as span:
            pa = PendingAction(
                id=self._new_id(session),
                kind=kind,
                summary=summary,
                payload=payload,
            )
            session.pending_actions[pa.id] = pa
            logger.info("HITL: created pending_action id=%s kind=%s", pa.id, kind)
            span.set_attribute("hitl.pending_action_id", pa.id)
            span.set_attribute("hitl.pending_count_after", len(session.pending_actions))
            return pa

    def get(self, session: SessionState, action_id: str) -> Optional[PendingAction]:
        with traced(
            "security.hitl.get_pending",
            attributes={
                "app.mode": "patched",
                "hitl.action_id": action_id,
            },
        ) as span:
            pending = session.pending_actions.get(action_id)
            span.set_attribute("hitl.found", pending is not None)
            return pending

    def cancel(self, session: SessionState, action_id: str) -> bool:
        with traced(
            "security.hitl.cancel_pending",
            attributes={
                "app.mode": "patched",
                "hitl.action_id": action_id,
            },
        ) as span:
            if action_id in session.pending_actions:
                del session.pending_actions[action_id]
                logger.info("HITL: canceled pending_action id=%s", action_id)
                span.set_attribute("hitl.canceled", True)
                span.set_attribute("hitl.pending_count_after", len(session.pending_actions))
                return True
            span.set_attribute("hitl.canceled", False)
            return False

    def pop(self, session: SessionState, action_id: str) -> Optional[PendingAction]:
        with traced(
            "security.hitl.consume_pending",
            attributes={
                "app.mode": "patched",
                "hitl.action_id": action_id,
            },
        ) as span:
            pending = session.pending_actions.pop(action_id, None)
            span.set_attribute("hitl.found", pending is not None)
            span.set_attribute("hitl.pending_count_after", len(session.pending_actions))
            return pending

    def _new_id(self, session: SessionState) -> str:
        # stable-ish short id for stage demos
        return f"a{len(session.pending_actions)+1}"
