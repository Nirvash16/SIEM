"""Mitigation executor — the single choke-point that applies firewall/IPS/DDoS rules.

Enforces the HITL rule: high-risk changes only execute when a human approval is
attached (approved_by_human). Tier-1 temporary mitigations may run autonomously.
Every execution writes a firewall_policy_changes record + audit trail entry and
publishes to the event bus for the live trigger feed.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any, Dict, Optional

from app.config import settings
from app.schemas.security import (
    ActionProposal, ActionStatus, FirewallPolicyChange, utcnow,
)
from app.services.event_bus import bus, repo


async def execute_mitigation(
    proposal: ActionProposal,
    approved_by_human: Optional[str] = None,
    applied_by_agent: str = "Firewall_IPS_Agent",
    device_id: str = "edge-ngfw-pa5400-01",
) -> Dict[str, Any]:
    rule = proposal.firewall_rule
    if rule is None:
        raise ValueError("Proposal carries no executable rule")

    # --- HITL safety gate ------------------------------------------------------
    # Tier-1 + temporary ⇒ autonomous reversible mitigation. Everything else
    # (permanent rewrites, BGP/NGFW control-plane changes, Tiers 2–3) needs a human.
    is_temporary = rule.duration_seconds is not None
    high_risk = (
        int(proposal.tier) >= 2
        or not is_temporary
        or rule.enforcement_layer.value in ("BGP_FLOWSPEC", "NGFW_API")
    )
    if high_risk and not approved_by_human:
        raise PermissionError(
            "HITL violation: high-risk intrusive change requires explicit human confirmation."
        )

    expires_at = utcnow() + timedelta(seconds=rule.duration_seconds) if rule.duration_seconds else None

    change = FirewallPolicyChange(
        id=str(uuid.uuid4()),
        incident_id=proposal.incident_id,
        device_id=device_id,
        rule_type=rule.action,
        rule_definition={
            "src": rule.src_ip_cidr,
            "dst": rule.dst_ip_cidr,
            "port": rule.dst_port,
            "proto": rule.protocol,
            "action": f"{rule.action.value.lower()}_{(rule.rate_limit_pps or 'full')}",
            "layer": rule.enforcement_layer.value,
            "suricata_sid": rule.suricata_rule_sid,
            "preview": rule.rule_definition_preview,
        },
        enforcement_layer=rule.enforcement_layer,
        applied_by_agent=applied_by_agent,
        approved_by_human=approved_by_human,
        expires_at=expires_at,
    )
    repo.add_policy_change(change)
    proposal.status = ActionStatus.EXECUTED
    repo.save_proposal(proposal)

    repo.audit(applied_by_agent, "MITIGATION_EXECUTED", {
        "proposal_id": proposal.proposal_id, "rule_id": rule.rule_id,
        "layer": rule.enforcement_layer.value, "action": rule.action.value,
        "approved_by_human": approved_by_human, "expires_at": expires_at.isoformat() if expires_at else "permanent",
    })
    await bus.publish("mitigations", {
        "type": "POLICY_APPLIED",
        "incident_id": proposal.incident_id,
        "rule_id": rule.rule_id,
        "action": rule.action.value,
        "layer": rule.enforcement_layer.value,
        "preview": rule.rule_definition_preview,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "autonomous": approved_by_human is None,
    })
    return {"change_id": change.id, "status": "EXECUTED", "expires_at": expires_at}


async def rollback_mitigation(change_id: str, actor: str) -> Dict[str, Any]:
    change = repo.policy_changes.get(change_id)
    if not change:
        raise KeyError(f"policy change {change_id} not found")
    change.rolled_back = True
    repo.audit(actor, "MITIGATION_ROLLBACK", {"change_id": change_id, "rule": change.rule_definition.get("action")})
    await bus.publish("mitigations", {"type": "POLICY_ROLLED_BACK", "change_id": change_id, "actor": actor})
    return {"change_id": change_id, "status": "ROLLED_BACK"}
