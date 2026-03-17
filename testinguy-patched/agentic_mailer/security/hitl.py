from __future__ import annotations

import logging
from typing import Optional

from ..session_store import PendingAction, SessionState

logger = logging.getLogger(__name__)


class HITLManager:
    """Human-in-the-loop confirmation manager.

    Stores pending actions in the user's session.
    """

    def create_pending(self, session: SessionState, kind: str, summary: str, payload: dict) -> PendingAction:
        pa = PendingAction(
            id=self._new_id(session),
            kind=kind,
            summary=summary,
            payload=payload,
        )
        session.pending_actions[pa.id] = pa
        logger.info("HITL: created pending_action id=%s kind=%s", pa.id, kind)
        return pa

    def get(self, session: SessionState, action_id: str) -> Optional[PendingAction]:
        return session.pending_actions.get(action_id)

    def cancel(self, session: SessionState, action_id: str) -> bool:
        if action_id in session.pending_actions:
            del session.pending_actions[action_id]
            logger.info("HITL: canceled pending_action id=%s", action_id)
            return True
        return False

    def pop(self, session: SessionState, action_id: str) -> Optional[PendingAction]:
        return session.pending_actions.pop(action_id, None)

    def _new_id(self, session: SessionState) -> str:
        # stable-ish short id for stage demos
        return f"a{len(session.pending_actions)+1}"
