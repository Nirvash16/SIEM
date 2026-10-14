"""Main CISO AI Agent — the hierarchical validation gate.

Aggregates Sector-Agent hypotheses, validates evidence provenance, models total
blast radius / business risk, and formulates structured Action Proposals for
human sign-off. STRICT RULE: zero high-risk intrusive changes execute without
explicit human confirmation; only Tier-1 reversible mitigations run autonomously.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from app.agents.sector_agents import (
    AppSecAgent, CyberIntelAgent, DDoSAgent, DetectionIDSAgent,
    FirewallIPSAgent, HoneypotAgent, PatchAssistantAgent,
)
from app.config import settings
from app.schemas.security import (
    ActionProposal, ActionStatus, AttackClass, BlastRadiusNode, IDSEvent,
    IncidentDossier, IncidentStatus, TierLevel,
)


class CISOMainAgent:
    def __init__(self) -> None:
        self.fw_ips_ddos_agent = FirewallIPSAgent()
        self.ddos_agent = DDoSAgent()
        self.detection_agent = DetectionIDSAgent()
        self.intel_agent = CyberIntelAgent()
        self.honeypot_agent = HoneypotAgent()
        self.appsec_agent = AppSecAgent()
        self.patch_agent = PatchAssistantAgent()

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _validate_provenance(events: List[IDSEvent]) -> List[str]:
        """Every claim must trace back to a named sensor + timestamp."""
        gaps: List[str] = []
        if not events:
            gaps.append("No raw telemetry attached — dossier is hypothesis-only.")
        for e in events:
            if not e.sensor_id:
                gaps.append(f"Alert '{e.signature_name}' missing sensor provenance.")
        return gaps

    @staticmethod
    def _blast_radius(attack_class: AttackClass, victim_ip: str, tier: TierLevel) -> List[BlastRadiusNode]:
        radius = [
            BlastRadiusNode(entity="Ingress Edge Router 01", entity_type="FIREWALL", impact="LOW"),
            BlastRadiusNode(entity=f"{victim_ip} (payments-ingress VIP)", entity_type="HOST",
                            impact="HIGH" if tier == TierLevel.TIER_3 else "MEDIUM"),
            BlastRadiusNode(entity="checkout-web microservice", entity_type="SERVICE", impact="MEDIUM"),
        ]
        if attack_class == AttackClass.VOLUMETRIC:
            radius.append(BlastRadiusNode(entity="Upstream Scrubbing Provider (CF/Akamai)",
                                          entity_type="CDN", impact="LOW"))
            radius.append(BlastRadiusNode(entity="Payments Business Unit", entity_type="BUSINESS_UNIT",
                                          impact="CRITICAL" if tier == TierLevel.TIER_3 else "HIGH"))
        if tier == TierLevel.TIER_3:
            radius.append(BlastRadiusNode(entity="BGP Control Plane", entity_type="FIREWALL", impact="CRITICAL"))
        return radius

    # ------------------------------------------------------------- evaluation
    async def evaluate_incident(self, incident_id: str, raw_ids_data: List[Dict[str, Any]]) -> IncidentDossier:
        ids_events = [IDSEvent(**e) for e in raw_ids_data]

        # 1. Automated DDoS detection first — Comprehensive Network Visibility tenet.
        ddos_analysis = self.ddos_agent.analyze(incident_id, ids_events)
        # 2. Intrusion analysis from perimeter/firewall/IPS agent.
        fw_analysis = self.fw_ips_ddos_agent.analyze_intrusion(incident_id, ids_events)
        # 3. Supporting sector agents enrich the dossier.
        detection = self.detection_agent.analyze(incident_id, ids_events)
        intel = self.intel_agent.analyze(incident_id, ids_events)
        appsec = self.appsec_agent.analyze(incident_id, ids_events)

        traces = ddos_analysis["traces"] + fw_analysis["traces"] + detection["traces"] + intel["traces"] + appsec["traces"]

        # 4. CISO synthesis: pick dominant threat & tier.
        if ddos_analysis["is_ddos"]:
            dominant = ddos_analysis
            attack_class: AttackClass = ddos_analysis["attack_class"]
            tier = max(dominant["tier"], fw_analysis["tier"], key=int)
            title = f"DDoS Alert ({attack_class.value}): {dominant['detected_signature']}"
            sector = "DDoS_Mitigation" if attack_class != AttackClass.NONE else "Firewall_IDS_IPS_DDOS"
        else:
            dominant = fw_analysis
            attack_class = AttackClass.NONE
            tier = fw_analysis["tier"]
            title = f"Alert: {dominant['detected_signature']}"
            sector = "Firewall_IDS_IPS_DDOS"

        provenance_gaps = self._validate_provenance(ids_events)
        data_gaps = provenance_gaps + detection["data_gaps"]

        # Confidence: base per tier, adjusted by corroboration across agents.
        confidence = {TierLevel.TIER_1: 0.87, TierLevel.TIER_2: 0.91, TierLevel.TIER_3: 0.94}[tier]
        if len({t.agent_name for t in traces}) >= 4:
            confidence = min(0.98, confidence + 0.02)
        if provenance_gaps:
            confidence = max(0.5, confidence - 0.15)

        proposal: ActionProposal | None = None
        rules = dominant.get("rules") or []
        if rules:
            rule = rules[0]
            victim_ip = dominant.get("victim_ip", "10.0.0.0")
            target_ip = dominant["target_ip"]
            if attack_class != AttackClass.NONE:
                proposed_action = (
                    f"Apply temporary {rule.action.value} mitigation for volumetric source range against "
                    f"{victim_ip} (auto-expiry {rule.duration_seconds}s)"
                )
                deps = ["Ingress Edge Router 01", "Upstream Scrubbing Provider", "BGP Flowspec controller"]
            else:
                proposed_action = f"Apply temporary mitigation rule for {target_ip}"
                deps = ["Ingress Edge Router 01", "NGFW Cluster A (Palo Alto PA-5400)"]

            proposal = ActionProposal(
                proposal_id=f"prop-{hashlib.md5(incident_id.encode()).hexdigest()[:12]}",
                incident_id=incident_id,
                target_entity=f"Network Edge (Target: {target_ip}, Victim: {victim_ip})",
                proposed_action=proposed_action,
                tier=tier,
                attack_class=attack_class,
                firewall_rule=rule,
                expected_security_benefit=dominant["benefit"] or fw_analysis["benefit"],
                business_impact_analysis=(
                    "Low impact: single external source range rate-limited/blocked; JS-challenge path keeps "
                    "verified humans online. Zero internal-user disruption projected. Reversible via expiry."
                ),
                downstream_dependencies=deps,
                rollback_steps=[
                    f"Execute API command: delete firewall/ddos policy rule-id {rule.rule_id}",
                    "Revert BGP flowspec announcement / withdraw scrubbing route",
                    "Confirm legitimate traffic baseline restored via NetFlow visibility check",
                ],
                required_approvers=["Network_Security_Lead", "Human_CISO"],
                blast_radius=self._blast_radius(attack_class, victim_ip, tier),
            )

        summary_parts = [
            "Network IDS/DDoS detection triggered. Agents generated targeted mitigation based on "
            "comprehensive traffic visibility (NetFlow/sFlow/eBPF baselines)."
        ]
        if attack_class != AttackClass.NONE:
            m = ddos_analysis["metrics"]
            summary_parts.append(
                f"Peak visibility: {m['peak_bps']:,} bps / {m['peak_pps']:,} pps / {m['peak_rps']:,} rps → "
                f"{attack_class.value} classification."
            )
        summary_parts.append(f"Intel: {intel['attribution']}. Exposure: {intel['financial_exposure']}.")

        status = IncidentStatus.PENDING_APPROVAL if (proposal and tier != TierLevel.TIER_1) else IncidentStatus.INVESTIGATING
        if tier == TierLevel.TIER_1 and proposal:
            status = IncidentStatus.RESOLVED  # autonomous execution happens at ingest endpoint

        dossier = IncidentDossier(
            incident_id=incident_id,
            title=title,
            tier=tier,
            sector=sector,
            status=status,
            summary=" ".join(summary_parts),
            confidence_score=round(confidence, 3),
            attack_class=attack_class,
            ddos_metrics=ddos_analysis["metrics"],
            ids_events=ids_events,
            queries_executed=detection["queries_executed"],
            data_gaps=data_gaps,
            agent_traces=traces,
            proposal=proposal,
        )
        return dossier

    # ------------------------------------------------------- HITL enforcement
    @staticmethod
    def enforce_hitl_gate(dossier: IncidentDossier) -> bool:
        """True when the platform may execute WITHOUT a human. Tier 1 only,
        temporary duration, reversible. Everything else awaits sign-off."""
        p = dossier.proposal
        if not p or not p.firewall_rule:
            return False
        if dossier.tier != TierLevel.TIER_1:
            return False
        if p.firewall_rule.duration_seconds is None:  # permanent rewrite ⇒ human gate
            return False
        return settings.tier1_autonomous_execution


ciso_agent = CISOMainAgent()
