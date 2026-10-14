"""CISO Action Approval Queue — the Human-in-the-Loop gate endpoints."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from app.schemas.security import (
    ActionStatus, FirewallRuleProposal, HumanActionReview, IncidentStatus, ReviewRequest, utcnow,
)
from app.services.event_bus import bus, repo
from app.services.mitigation_executor import execute_mitigation, rollback_mitigation
from app.services.training_pipeline import maybe_trigger_fine_tuning

router = APIRouter(prefix="/api/v1/approvals", tags=["approvals"])


@router.get("/queue")
async def approval_queue() -> List[Dict[str, Any]]:
    """Priority-ordered card queue of pending remediation proposals."""
    return [p.model_dump(mode="json") for p in repo.pending_approvals()]


@router.get("/{proposal_id}")
async def get_proposal(proposal_id: str) -> Dict[str, Any]:
    proposal = repo.proposals.get(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail=f"Proposal {proposal_id} not found")
    reviews = [r.model_dump(mode="json") for r in repo.reviews if r.proposal_id == proposal_id]
    return {"proposal": proposal.model_dump(mode="json"), "review_history": reviews}


@router.post("/{proposal_id}/review")
async def review_action_proposal(proposal_id: str, req: ReviewRequest) -> Dict[str, Any]:
    """Human sign-off. APPROVED → executes network change; REJECTED → escalates.
    Every decision is logged as RLHF feedback for the SFT/DPO pipeline."""
    proposal = repo.proposals.get(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail=f"Proposal {proposal_id} not found")
    if proposal.status == ActionStatus.EXECUTED:
        raise HTTPException(status_code=409, detail="Proposal already executed")
    if req.action not in (ActionStatus.APPROVED, ActionStatus.REJECTED):
        raise HTTPException(status_code=400, detail="Action must be APPROVED or REJECTED")

    result: Dict[str, Any] = {"status": "SUCCESS", "proposal_id": proposal_id,
                              "action_taken": req.action.value, "reviewer_id": req.reviewer_id,
                              "timestamp": utcnow().isoformat()}

    if req.action == ActionStatus.APPROVED:
        try:
            execution = await execute_mitigation(
                proposal, approved_by_human=req.reviewer_id, applied_by_agent="CISO_Agent(human-approved)")
            result["execution"] = {"change_id": str(execution["change_id"]),
                                   "expires_at": execution["expires_at"].isoformat() if execution["expires_at"] else None}
            incident = repo.incidents.get(proposal.incident_id)
            if incident:
                incident.status = IncidentStatus.RESOLVED
                repo.save_incident(incident)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    else:
        proposal.status = ActionStatus.REJECTED
        repo.save_proposal(proposal)
        result["escalation"] = "Routed to Incident Response team + Tier-3 deep multi-agent synthesis."

    review = HumanActionReview(
        id=str(uuid.uuid4()),
        incident_id=proposal.incident_id,
        proposal_id=proposal_id,
        proposed_action={
            "proposed_action": proposal.proposed_action,
            "rule_preview": proposal.firewall_rule.rule_definition_preview if proposal.firewall_rule else "",
            "tier": int(proposal.tier), "attack_class": proposal.attack_class.value,
        },
        business_impact_analysis={"summary": proposal.business_impact_analysis,
                                  "blast_radius": [b.model_dump() for b in proposal.blast_radius]},
        action_taken=req.action,
        reviewer_id=req.reviewer_id,
        human_feedback_notes=req.feedback_notes,
    )
    repo.add_review(review)
    repo.audit(req.reviewer_id, f"HITL_{req.action.value}", {"proposal_id": proposal_id})
    await bus.publish("approvals", {"type": "HITL_DECISION", "proposal_id": proposal_id,
                                    "action": req.action.value, "reviewer": req.reviewer_id})

    training = await maybe_trigger_fine_tuning()
    if training:
        result["training_job_queued"] = training.job_id
    return result


@router.patch("/{proposal_id}/rule")
async def edit_proposal_rule(proposal_id: str, rule: FirewallRuleProposal) -> Dict[str, Any]:
    """[Edit Proposal] — analysts adjust rule parameters before approving (diff re-rendered in UI)."""
    proposal = repo.proposals.get(proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail=f"Proposal {proposal_id} not found")
    if proposal.status == ActionStatus.EXECUTED:
        raise HTTPException(status_code=409, detail="Cannot edit an executed proposal")
    proposal.firewall_rule = rule
    repo.save_proposal(proposal)
    await bus.publish("approvals", {"type": "PROPOSAL_EDITED", "proposal_id": proposal_id,
                                    "rule_id": rule.rule_id})
    return {"status": "MODIFIED", "proposal": proposal.model_dump(mode="json")}


@router.post("/{proposal_id}/rollback/{change_id}")
async def rollback(proposal_id: str, change_id: str, reviewer_id: str = "Human_CISO") -> Dict[str, Any]:
    """Rollback Safety Check control — reverses an executed mitigation."""
    try:
        return await rollback_mitigation(change_id, actor=reviewer_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Policy change {change_id} not found")
