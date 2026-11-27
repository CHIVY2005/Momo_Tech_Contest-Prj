"""Pydantic contracts for VeriShield AI Assistant ("Trợ lý VeriShield")."""

from __future__ import annotations

from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

AssistantQuickIntent = Literal[
    "explain_report",
    "incident_response",
    "verify_info",
    "scam_education",
]

MAX_ASSISTANT_HISTORY_CHARS: Final[int] = 6000


class AssistantHistoryTurn(BaseModel):
    """Single untrusted prior conversation turn supplied by the web client."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=1200)


class AssistantChatRequest(BaseModel):
    """Strict request payload for POST /api/v1/assistant/chat/stream."""

    model_config = ConfigDict(extra="forbid")

    case_id: str | None = Field(default=None, max_length=80)
    message: str = Field(..., min_length=1, max_length=1500)
    history: list[AssistantHistoryTurn] = Field(default_factory=list, max_length=12)
    quick_intent: AssistantQuickIntent | None = None

    @model_validator(mode="after")
    def _validate_bounds(self) -> AssistantChatRequest:
        if not self.message.strip():
            raise ValueError("message must not be blank")
        total_history_chars = sum(len(turn.content) for turn in self.history)
        if total_history_chars > MAX_ASSISTANT_HISTORY_CHARS:
            raise ValueError(
                f"total history length exceeds {MAX_ASSISTANT_HISTORY_CHARS} characters"
            )
        return self


class AssistantCitation(BaseModel):
    """Grounded citation attached to an assistant response."""

    id: str
    source_type: Literal["kb", "case", "tool"]
    title: str
