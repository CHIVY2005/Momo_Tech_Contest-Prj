"""Closed-loop Fintech Fraud Ops (/radar) graph and block-rule contracts."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import IocType, VerdictLevel


class BlockRule(BaseModel):
    """Active ecosystem-wide block rule approved by Fraud Ops."""

    rule_id: str
    ioc_type: IocType
    masked_value: str
    reason: str
    created_at: str
    expires_at: str | None = None
    active: bool = True


class CreateBlockRuleRequest(BaseModel):
    """Payload to issue a 1-click or manual block rule on /radar."""

    ioc_type: IocType
    value: str | None = Field(default=None, min_length=3, max_length=255)
    ioc_hash: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    masked_value: str | None = Field(default=None, min_length=3, max_length=255)
    reason: str = Field(min_length=3, max_length=300)
    analyst_pin: str = Field(min_length=4, max_length=64)
    ttl_minutes: int | None = Field(default=None, ge=1, le=1440)

    @model_validator(mode="after")
    def _validate_target_present(self) -> "CreateBlockRuleRequest":
        has_raw = bool(self.value and self.value.strip())
        if not has_raw and self.ioc_hash is None:
            raise ValueError("Either raw 'value' or 'ioc_hash' must be provided.")
        return self


class ResetBlockRulesRequest(BaseModel):
    """Payload to reset transient demo block rules on /radar."""

    analyst_pin: str = Field(min_length=4, max_length=64)


class RadarNode(BaseModel):
    """Anonymized node in the Fraud Ops IOC threat graph."""

    node_id: str
    kind: Literal["phone", "bank_account", "domain", "campaign"]
    label: str
    hit_count: int = Field(default=1, ge=1)
    risk_level: VerdictLevel = "HIGH_RISK"
    blocked: bool = False


class RadarEdge(BaseModel):
    """Relationship edge between masked IOCs and emerging scam campaigns."""

    source: str
    target: str
    relation: str = "co_occurs"


class EmergingCampaign(BaseModel):
    """Clustered scam campaign surfaced in the Fraud Ops queue (zero raw PII)."""

    campaign_id: str
    title_vi: str
    playbook_id: str
    case_count: int = Field(default=1, ge=1)
    primary_ioc_type: IocType
    primary_ioc_masked: str
    primary_ioc_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    recommended_action: str
    already_blocked: bool = False


class RadarGraphResponse(BaseModel):
    """Full response powering the /radar Fraud Ops workspace."""

    nodes: list[RadarNode] = Field(default_factory=list)
    edges: list[RadarEdge] = Field(default_factory=list)
    campaigns: list[EmergingCampaign] = Field(default_factory=list)
    active_block_rules: list[BlockRule] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
