"""Incident ingest & dossier endpoints (network telemetry → CISO evaluation)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from app.agents.ciso_agent import ciso_agent
from app.schemas.security import (
    FirewallRuleProposal, IDSEvent, IncidentDossier, IncidentStatus, RuleAction, TierLevel, utcnow,
)
from app.services.event_bus import bus, repo
from app.services.mitigation_executor import execute_mitigation

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.post("/network-ingest", response_model=IncidentDossier)
async def ingest_network_alert(payload: Dict[str, Any]) -> IncidentDossier:
    incident_id = payload.get("incident_id", f"inc-{int(datetime.now(timezone.utc).timestamp())}")
    ids_logs = payload.get("ids_events", [])
    if not isinstance(ids_logs, list):
        raise HTTPException(status_code=422, detail="ids_events must be a list")

    dossier = await ciso_agent.evaluate_incident(incident_id, ids_logs)
    repo.save_incident(dossier)
    for trace in dossier.agent_traces:
        repo.add_trace(trace)
    for e in dossier.ids_events:  # persist raw telemetry to the historical attack DB
        repo.audit(e.sensor_id, "TELEMETRY_STORED", {
            "incident_id": incident_id, "src_ip": e.src_ip, "dst_ip": e.dst_ip,
            "signature_id": e.signature_id, "bps": e.traffic_volume_bps, "pps": e.packets_per_second,
        })

    if dossier.proposal:
        repo.save_proposal(dossier.proposal)

        # Tier 1 Autonomous Resolution — temporary, reversible rules only.
        if dossier.tier == TierLevel.TIER_1 and ciso_agent.enforce_hitl_gate(dossier):
            try:
                result = await execute_mitigation(dossier.proposal, approved_by_human=None,
                                                  applied_by_agent=dossier.proposal.attack_class.value or "DDoS_Agent")
                dossier.status = IncidentStatus.RESOLVED
                repo.audit("CISO_Agent", "TIER1_AUTONOMOUS_EXECUTION",
                           {"incident_id": incident_id, "change_id": result["change_id"]})
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc))
        else:
            dossier.status = IncidentStatus.PENDING_APPROVAL

    repo.save_incident(dossier)
    await bus.publish("incidents", {
        "type": "INCIDENT_EVALUATED", "incident_id": incident_id, "tier": int(dossier.tier),
        "attack_class": dossier.attack_class.value, "status": dossier.status.value,
        "confidence": dossier.confidence_score, "title": dossier.title,
        "proposal_id": dossier.proposal.proposal_id if dossier.proposal else None,
    })
    return dossier


@router.get("", response_model=List[IncidentDossier])
async def list_incidents(tier: int | None = None, status: str | None = None,
                         sector: str | None = None) -> List[IncidentDossier]:
    out = list(repo.incidents.values())
    if tier is not None:
        out = [d for d in out if int(d.tier) == tier]
    if status:
        out = [d for d in out if d.status.value.lower() == status.lower()]
    if sector:
        out = [d for d in out if d.sector.lower() == sector.lower()]
    return sorted(out, key=lambda d: d.created_at, reverse=True)


@router.get("/{incident_id}", response_model=IncidentDossier)
async def get_dossier(incident_id: str) -> IncidentDossier:
    dossier = repo.incidents.get(incident_id)
    if not dossier:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return dossier


@router.get("/{incident_id}/traces")
async def get_traces(incident_id: str) -> List[Dict[str, Any]]:
    traces = [t for t in repo.traces if t.incident_id == incident_id]
    return [t.model_dump(mode="json") for t in sorted(traces, key=lambda x: (x.agent_name, x.step_number))]
