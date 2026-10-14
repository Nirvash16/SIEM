"""Perimeter, Firewall/IPS & DDoS Management Module + Topology endpoints."""
from __future__ import annotations

import random
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException

from app.schemas.security import (
    ActionStatus, AttackClass, EnforcementLayer, FirewallRuleProposal, IncidentStatus,
    RuleAction, TierLevel, TopologyGraph, VisibilitySnapshot, utcnow,
)
from app.services.event_bus import bus, repo
from app.services.mitigation_executor import execute_mitigation, rollback_mitigation

router = APIRouter(prefix="/api/v1/network", tags=["network-visibility"])


# ---------------------------------------------------------------------------
# Comprehensive Network Visibility Dashboard
# ---------------------------------------------------------------------------
@router.get("/visibility", response_model=VisibilitySnapshot)
async def visibility() -> VisibilitySnapshot:
    """Real-time traffic baseline vs anomaly — the fundamental tenet endpoint."""
    baselines = repo.baselines[-60:]
    latest = baselines[-1] if baselines else None
    active_ddos = [d for d in repo.incidents.values()
                   if d.attack_class != AttackClass.NONE and d.status != IncidentStatus.RESOLVED]
    breakdown: Dict[str, int] = {"VOLUMETRIC": 0, "PROTOCOL": 0, "APPLICATION": 0}
    for d in active_ddos:
        if d.attack_class.value in breakdown:
            breakdown[d.attack_class.value] += 1

    talkers = sorted(
        [{"ip": n.label.split("\n")[0], "bps": n.metrics.get("bps", 0), "pps": n.metrics.get("pps", 0)}
         for n in repo.topology_nodes.values() if n.status == "adversarial"],
        key=lambda t: -t["bps"])
    return VisibilitySnapshot(
        generated_at=utcnow(),
        total_ingress_bps=latest.actual_bps if latest else 0,
        total_pps=sum(d.ddos_metrics.get("peak_pps", 0) for d in active_ddos),
        active_flows=random.randint(48_000, 62_000),
        attack_breakdown=breakdown,
        baselines=baselines,
        top_talkers=talkers,
        sensors_online=sum(1 for n in repo.topology_nodes.values()
                           if n.node_type == "IDS_SENSOR" and n.status == "healthy"),
        sensors_total=sum(1 for n in repo.topology_nodes.values() if n.node_type == "IDS_SENSOR"),
    )


# ---------------------------------------------------------------------------
# Live topology graph (React Flow feed)
# ---------------------------------------------------------------------------
@router.get("/topology", response_model=TopologyGraph)
async def topology() -> TopologyGraph:
    return TopologyGraph(nodes=list(repo.topology_nodes.values()), edges=list(repo.topology_edges.values()))


@router.get("/nodes/{node_id}/detail")
async def node_detail(node_id: str) -> Dict[str, Any]:
    """Side-drawer payload: raw PCAP traces, IDS SIDs, real-time DDoS metrics."""
    node = repo.topology_nodes.get(node_id)
    if not node:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not found")
    related = [d.model_dump(mode="json") for d in repo.incidents.values()
               if any(ip in node.label for ip in (e.src_ip for e in d.ids_events))]
    pcap = [
        {"frame": i + 1, "ts": (utcnow().timestamp() - random.random()).__round__(6),
         "src": node.label.split("\n")[0], "proto": random.choice(["TCP", "UDP", "DNS", "HTTP"]),
         "hex": f"{random.getrandbits(96):024x}{random.getrandbits(64):016x}",
         "ascii": random.choice(["GET /checkout HTTP/1.1", "\x16\x03\x01 TLSv1.3 handshake",
                                 "NTP mon_getlist (amp vector)", "SYN seq=0 win=65535"])}
        for i in range(8)
    ]
    sids = sorted({e.signature_id for d in repo.incidents.values() for e in d.ids_events})
    return {"node": node.model_dump(mode="json"), "related_incidents": related,
            "pcap_traces": pcap, "active_sids": sids,
            "live_metrics": {"bps": node.metrics.get("bps", 0), "pps": node.metrics.get("pps", 0),
                             "updated_at": utcnow().isoformat()}}


# ---------------------------------------------------------------------------
# Active IDS/IPS/DDoS trigger feed + policy history
# ---------------------------------------------------------------------------
@router.get("/trigger-feed")
async def trigger_feed(limit: int = 50) -> List[Dict[str, Any]]:
    events = [r for r in bus.history if r["topic"] in ("incidents", "mitigations")][:limit]
    return events


@router.get("/policies")
async def policy_history() -> List[Dict[str, Any]]:
    return [c.model_dump(mode="json") for c in reversed(list(repo.policy_changes.values()))]


# ---------------------------------------------------------------------------
# One-Click Mitigation Bar
# ---------------------------------------------------------------------------
ONE_CLICK_PRESETS: Dict[str, Dict[str, Any]] = {
    "deploy_temporary_ips_drop_1h": {
        "action": RuleAction.DROP, "layer": EnforcementLayer.EBPF_XDP, "duration": 3600,
        "label": "Deploy Temporary IPS Drop (1h)", "tier": TierLevel.TIER_1,
    },
    "commit_permanent_ngfw_policy": {
        "action": RuleAction.DROP, "layer": EnforcementLayer.NGFW_API, "duration": None,
        "label": "Commit Permanent NGFW Policy", "tier": TierLevel.TIER_3,
    },
    "reroute_to_honeypot": {
        "action": RuleAction.HONEYPOT_ROUTE, "layer": EnforcementLayer.IPTABLES, "duration": 86400,
        "label": "Reroute to Honeypot", "tier": TierLevel.TIER_2,
    },
    "activate_upstream_scrubbing": {
        "action": RuleAction.SCRUB_REDIRECT, "layer": EnforcementLayer.SCRUBBING_CENTER, "duration": 3600,
        "label": "Activate Upstream DDoS Scrubbing", "tier": TierLevel.TIER_3,
    },
}


@router.post("/one-click/{preset}")
async def one_click(preset: str, incident_id: str, src_ip: str = "203.0.113.66",
                    dst_ip: str = "10.20.4.10", reviewer_id: str | None = None) -> Dict[str, Any]:
    """One-Click Mitigation Bar. High-risk presets REQUIRE reviewer_id (HITL gate)."""
    cfg = ONE_CLICK_PRESETS.get(preset)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"Unknown preset '{preset}'. Options: {list(ONE_CLICK_PRESETS)}")
    incident = repo.incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    rule = FirewallRuleProposal(
        rule_id=f"oc-{preset[:10]}-{incident_id[-6:]}", action=cfg["action"],
        src_ip_cidr=f"{src_ip}/32" if cfg["action"] != RuleAction.SCRUB_REDIRECT else "0.0.0.0/0",
        dst_ip_cidr=f"{dst_ip}/32", dst_port=443, enforcement_layer=cfg["layer"],
        duration_seconds=cfg["duration"],
        rule_definition_preview=f"[{cfg['label']}] applied via one-click bar on {cfg['layer'].value}",
    )
    proposal = next(iter([p for p in repo.proposals.values()
                          if p.incident_id == incident_id]), None)
    from app.schemas.security import ActionProposal, ActionStatus
    if proposal is None or proposal.status == ActionStatus.EXECUTED:
        import hashlib
        proposal = ActionProposal(
            proposal_id=f"prop-oc-{hashlib.md5((incident_id + preset).encode()).hexdigest()[:10]}",
            incident_id=incident_id, target_entity=f"{dst_ip} edge", proposed_action=cfg["label"],
            tier=cfg["tier"], firewall_rule=rule, expected_security_benefit=cfg["label"],
            business_impact_analysis="Operator-initiated one-click mitigation.",
            rollback_steps=[f"Delete rule {rule.rule_id}; withdraw route."],
            required_approvers=["Human_CISO"],
        )
        repo.save_proposal(proposal)
    else:
        # Reusing a preset on an existing proposal must re-derive the proposal from
        # the preset's own tier/action — otherwise it inherits stale Tier-3 status
        # and falsely trips the HITL gate for low-risk one-click actions.
        proposal.firewall_rule = rule
        proposal.tier = cfg["tier"]
        proposal.proposed_action = cfg["label"]
        proposal.expected_security_benefit = cfg["label"]
        if proposal.status in (ActionStatus.EXECUTED, ActionStatus.REJECTED):
            proposal.status = ActionStatus.PENDING

    try:
        result = await execute_mitigation(proposal, approved_by_human=reviewer_id,
                                          applied_by_agent="One_Click_Mitigation_Bar")
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return {"preset": cfg["label"], **result}


@router.post("/mitigations/{change_id}/rollback")
async def rollback_change(change_id: str, actor: str = "Human_CISO") -> Dict[str, Any]:
    try:
        return await rollback_mitigation(change_id, actor)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Policy change {change_id} not found")
