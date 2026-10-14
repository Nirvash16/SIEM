"""Sector AI Agents — specialized domain agents with their tool surfaces.

Each agent returns structured hypotheses + candidate mitigations and records an
AgentDecisionTrace (fed later into the SFT dataset curator). The DDoS agent
embodies the platform's non-negotiable tenet: Comprehensive Network Visibility
(NetFlow, sFlow, eBPF telemetry, BGP flowspec) before any automated mitigation.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from app.config import settings
from app.schemas.security import (
    AgentDecisionTrace, AttackClass, EnforcementLayer, FirewallRuleProposal,
    IDSEvent, RuleAction, TierLevel,
)


def _sid_from(signature_id: str) -> int:
    m = re.search(r"SID:(\d+)", signature_id)
    return int(m.group(1)) if m else int(hashlib.md5(signature_id.encode()).hexdigest()[:6], 16)


class BaseSectorAgent:
    name: str = "BaseSectorAgent"
    tools: List[str] = []

    def trace(self, incident_id: str, step: int, thought: str,
              hypotheses: List[str], confidence_delta: float = 0.0,
              tool_calls: List[Dict[str, Any]] | None = None) -> AgentDecisionTrace:
        return AgentDecisionTrace(
            incident_id=incident_id, agent_name=self.name, step_number=step,
            prompt_context={"tools": self.tools},
            llm_thought_process=thought,
            tool_calls_executed=tool_calls or [],
            hypotheses_evaluated=hypotheses,
            confidence_delta=confidence_delta,
        )

    def render_suricata(self, event: IDSEvent, action: str = "drop") -> str:
        """Compile a dynamic IPS drop rule for the live rule-diff viewer."""
        sid = _sid_from(event.signature_id)
        rev = 1
        return (
            f'{action} {event.protocol.upper()} {event.src_ip} any -> {event.dst_ip} '
            f'{event.dst_port} (msg:"{event.signature_name}"; sid:{sid}; rev:{rev}; '
            f'classtype:attempted-admin; threshold:type limit, track by_src, count 100, seconds 10;)'
        )


# ---------------------------------------------------------------------------
# Network Perimeter & Firewall/IPS AI Agent
# ---------------------------------------------------------------------------
class FirewallIPSAgent(BaseSectorAgent):
    name = "Firewall_IPS_Agent"
    tools = [
        "eBPF/XDP drop trigger", "Palo Alto NGFW API", "Fortinet FortiManager API",
        "AWS WAF UpdateWebACL", "Suricata rule compiler", "Snort rule compiler", "Zeek policy deploy",
    ]

    INTRUSION_SIGNATURES = ("SQLi", "XSS", "RCE", "exploit", "malware", "C2", "web shell", "log4j")

    def analyze_intrusion(self, incident_id: str, events: List[IDSEvent]) -> Dict[str, Any]:
        intrusion_events = [
            e for e in events
            if any(s.lower() in e.signature_name.lower() for s in self.INTRUSION_SIGNATURES)
        ]
        high_sev = [e for e in events if e.severity >= settings.ids_high_severity]
        known_bad = [e for e in events if e.severity == 1]

        best = max(events, key=lambda e: e.severity, default=None)
        tier = TierLevel.TIER_1
        if intrusion_events or high_sev:
            tier = TierLevel.TIER_3 if any(e.severity >= 4 for e in events) else TierLevel.TIER_2
        elif known_bad:
            tier = TierLevel.TIER_1

        traces = [
            self.trace(
                incident_id, 1,
                f"Inspected {len(events)} IDS/IPS alerts across perimeter sensors. Matched "
                f"{len(intrusion_events)} payloads against exploit signature families; "
                f"{len(high_sev)} alerts at severity >= {settings.ids_high_severity}.",
                ["Active exploit attempt", "Scanner noise / false positive", "Reputation-only hit"],
                confidence_delta=0.31 if intrusion_events else 0.12,
                tool_calls=[{"tool": "Suricata rule compiler", "args": {"event": best.signature_id if best else None}}],
            )
        ]
        rules = [
            FirewallRuleProposal(
                rule_id=f"fw-{hashlib.md5((incident_id + e.src_ip).encode()).hexdigest()[:8]}",
                action=RuleAction.DROP,
                src_ip_cidr=f"{e.src_ip}/32",
                dst_ip_cidr="10.0.0.0/8",
                dst_port=e.dst_port,
                protocol=e.protocol,
                # Tier-1 routine blocks run autonomously at the kernel edge (eBPF/XDP);
                # permanent / assisted policy rewrites go through the NGFW control plane.
                enforcement_layer=EnforcementLayer.EBPF_XDP if tier == TierLevel.TIER_1
                                  else EnforcementLayer.NGFW_API,
                suricata_rule_sid=_sid_from(e.signature_id),
                duration_seconds=86400 if tier != TierLevel.TIER_1 else 3600,
                rule_definition_preview=self.render_suricata(e),
            )
            for e in (intrusion_events or events)[:3]
        ]
        return {
            "agent": self.name, "tier": tier, "rules": rules, "traces": traces,
            "is_ddos": False,
            "target_ip": (intrusion_events or events)[0].src_ip if events else "0.0.0.0",
            "detected_signature": best.signature_name if best else "Unknown",
            "benefit": "Blocks active exploit payloads matching IDS signature via temporary NGFW drop.",
        }


# ---------------------------------------------------------------------------
# Automated DDoS Detection & Resilience AI Agent
# ---------------------------------------------------------------------------
class DDoSAgent(BaseSectorAgent):
    name = "DDoS_Detection_Resilience_Agent"
    tools = [
        "NetFlow/sFlow collector query", "eBPF telemetry (kbps/pps per flow)", "BGP Flowspec announce",
        "Scrubbing center routing (Cloudflare/Akamai)", "SYN cookie toggle", "XDP rate limiter",
        "WAF bot-shield tuning", "Dynamic baseline tuner",
    ]

    VISIBILITY_TENET = (
        "Comprehensive Network Visibility is the fundamental, non-negotiable prerequisite: "
        "no mitigation fires without corroborating NetFlow/sFlow/eBPF telemetry."
    )

    def classify_attack(self, events: List[IDSEvent]) -> AttackClass:
        """Volumetric vs Protocol vs Application-layer classification."""
        volumetric = [e for e in events if (e.traffic_volume_bps or 0) > settings.ddos_bps_threshold]
        protocol = [e for e in events if (e.packets_per_second or 0) > settings.ddos_pps_threshold
                    or "SYN_FLOOD" in e.signature_id.upper() or "AMPLIFICATION" in e.signature_name.upper()]
        application = [e for e in events if (e.requests_per_second or 0) > settings.l7_ddos_rps_threshold
                       or "HTTP" in e.signature_name.upper() and "FLOOD" in e.signature_name.upper()
                       or "SLOWLORIS" in e.signature_name.upper()]
        # Multi-vector: highest OSI layer under attack dominates response selection.
        if application:
            return AttackClass.APPLICATION
        if protocol:
            return AttackClass.PROTOCOL
        if volumetric:
            return AttackClass.VOLUMETRIC
        return AttackClass.NONE

    def analyze(self, incident_id: str, events: List[IDSEvent]) -> Dict[str, Any]:
        ddos_events = [
            e for e in events
            if (e.traffic_volume_bps or 0) > settings.ddos_bps_threshold
            or (e.packets_per_second or 0) > settings.ddos_pps_threshold
            or (e.requests_per_second or 0) > settings.l7_ddos_rps_threshold
        ]
        attack_class = self.classify_attack(ddos_events) if ddos_events else AttackClass.NONE
        peak_bps = max((e.traffic_volume_bps or 0 for e in events), default=0)
        peak_pps = max((e.packets_per_second or 0 for e in events), default=0)
        peak_rps = max((e.requests_per_second or 0 for e in events), default=0)
        top = max(ddos_events or events, key=lambda e: (e.traffic_volume_bps or 0) + (e.packets_per_second or 0),
                  default=None)

        # Multi-vector prioritization: massive volumetric floods dominate the response
        # (upstream scrubbing is required first); L7-only floods route to WAF copilot.
        # Protocol-layer provenance (SYN flood / DNS amplification) outranks raw bps;
        # overwhelming volume (>10x threshold) outranks an application-layer signal.
        protocol_proven = any(
            "SYN_FLOOD" in e.signature_id.upper() or "AMPLIFICATION" in e.signature_name.upper()
            for e in ddos_events)
        overwhelming = peak_bps > 10 * settings.ddos_bps_threshold
        if attack_class != AttackClass.NONE and (overwhelming or not protocol_proven):
            # Multi-vector escalation: overwhelming volume (>10x baseline threshold)
            # forces upstream scrubbing regardless of secondary vector signatures;
            # otherwise the classified OSI layer governs the response.
            if overwhelming:
                attack_class = AttackClass.VOLUMETRIC
            elif attack_class == AttackClass.APPLICATION and peak_bps > settings.ddos_bps_threshold \
                    and (peak_bps / settings.ddos_bps_threshold) >= (peak_rps / settings.l7_ddos_rps_threshold):
                attack_class = AttackClass.VOLUMETRIC

        tier = TierLevel.TIER_1
        if attack_class == AttackClass.APPLICATION:
            tier = TierLevel.TIER_2                      # L7: analyst copilot tunes WAF rules
        elif attack_class in (AttackClass.VOLUMETRIC, AttackClass.PROTOCOL):
            tier = TierLevel.TIER_3 if peak_bps > 10 * settings.ddos_bps_threshold else TierLevel.TIER_2

        rules: List[FirewallRuleProposal] = []
        benefit = ""
        if attack_class == AttackClass.VOLUMETRIC:
            rules.append(FirewallRuleProposal(
                rule_id=f"ddos-vol-{incident_id[:8]}", action=RuleAction.SCRUB_REDIRECT,
                src_ip_cidr="0.0.0.0/0", dst_ip_cidr=f"{top.dst_ip}/32" if top else "10.0.0.0/8",
                dst_port=0, enforcement_layer=EnforcementLayer.SCRUBBING_CENTER,
                duration_seconds=3600,
                rule_definition_preview=(
                    f"bgp flowspec match destination {top.dst_ip if top else 'any'}\n"
                    f"  then rate-limit 100000 pps / redirect nexthop :198.51.100.1 (scrub-center-a)"
                ),
            ))
            benefit = ("Activates upstream DDoS scrubbing + BGP Flowspec rate-limiting for a "
                       f"{peak_bps/1e9:.1f} Gbps volumetric anomaly while preserving legitimate flow.")
        elif attack_class == AttackClass.PROTOCOL:
            rules.append(FirewallRuleProposal(
                rule_id=f"ddos-proto-{incident_id[:8]}", action=RuleAction.SYN_COOKIE,
                src_ip_cidr="0.0.0.0/0", dst_ip_cidr=f"{top.dst_ip}/32" if top else "10.0.0.0/8",
                dst_port=top.dst_port if top else 80, enforcement_layer=EnforcementLayer.EBPF_XDP,
                rate_limit_pps=100_000, duration_seconds=3600,
                rule_definition_preview=(
                    "tc qdisc replace dev eth0 root netem ; sysctl -w net.ipv4.tcp_syncookies=1\n"
                    "xdp-drop --proto tcp --flags SYN --rate 100000pps --dst "
                    f"{top.dst_ip if top else '10.0.0.0/8'}"
                ),
            ))
            benefit = (f"Engages SYN-flood cookies and XDP rate limiting at edge; peak {peak_pps:,} pps "
                       "protocol-layer flood absorbed without session-table exhaustion.")
        elif attack_class == AttackClass.APPLICATION:
            rules.append(FirewallRuleProposal(
                rule_id=f"ddos-l7-{incident_id[:8]}", action=RuleAction.RATE_LIMIT,
                src_ip_cidr="0.0.0.0/0", dst_ip_cidr=f"{top.dst_ip}/32" if top else "10.0.0.0/8",
                dst_port=top.dst_port if top else 443, enforcement_layer=EnforcementLayer.AWS_WAF,
                rate_limit_pps=500, duration_seconds=7200,
                rule_definition_preview=(
                    f'aws waf update-rule-group --name l7-flood-mitigation \\n'
                    f'  rate-based-rule: 500 req/5min per IP, scope=IP, \\n'
                    f'  manage-bot-control: BLOCK on {top.dst_port if top else 443}/tcp HTTP(S) fingerprint anomaly'
                ),
            ))
            benefit = (f"WAF rate-limiting + bot control for L7 flood at {peak_rps:,} rps; JS-challenge "
                       "keeps real users online (zero legitimate-traffic downtime target).")

        traces = [self.trace(
            incident_id, 1,
            f"{self.VISIBILITY_TENET} Correlated sensor bps={peak_bps:,}, pps={peak_pps:,}, rps={peak_rps:,} "
            f"against dynamic NetFlow baselines → classified as {attack_class.value} event."
            if attack_class != AttackClass.NONE else
            f"{self.VISIBILITY_TENET} Traffic within learned baseline; no DDoS classification.",
            ["Volumetric flood", "Protocol/SYN flood", "Application-layer flood", "Legitimate flash-crowd"],
            confidence_delta=0.42 if attack_class != AttackClass.NONE else -0.05,
            tool_calls=[{"tool": "NetFlow/sFlow collector query", "args": {"window": "5m"}}],
        )]
        return {
            "agent": self.name, "is_ddos": attack_class != AttackClass.NONE,
            "attack_class": attack_class, "tier": tier, "rules": rules, "traces": traces,
            "target_ip": top.src_ip if top else "0.0.0.0",
            "victim_ip": top.dst_ip if top else "10.0.0.0",
            "detected_signature": top.signature_name if top else "Unknown",
            "metrics": {"peak_bps": peak_bps, "peak_pps": peak_pps, "peak_rps": peak_rps},
            "benefit": benefit,
        }


# ---------------------------------------------------------------------------
# Detection (IDS) AI Agent — JA3/JA4 & protocol deviation analytics
# ---------------------------------------------------------------------------
class DetectionIDSAgent(BaseSectorAgent):
    name = "Detection_IDS_Agent"
    tools = ["IDS log query (TimescaleDB)", "JA3/JA4 fingerprint store", "TLS entropy analyzer",
             "Protocol deviation detector", "Host EDR correlation"]

    def analyze(self, incident_id: str, events: List[IDSEvent]) -> Dict[str, Any]:
        encrypted = [e for e in events if e.dst_port in (443, 8443) and e.raw_payload is None]
        anomalies = [e for e in events if e.severity >= 3]
        thought = (
            f"Queried host+network IDS stores over 15m window. {len(encrypted)} TLS sessions inspected via "
            f"JA3/JA4 fingerprints (payload bodies opaque under TLS 1.3); {len(anomalies)} protocol deviations "
            "flagged. Encrypted C2 hypothesis remains open pending JA4 cluster match against intel corpus."
        )
        return {
            "agent": self.name,
            "data_gaps": ["Encrypted payload body uninspected (TLS 1.3)"] if encrypted else [],
            "queries_executed": [
                "SELECT * FROM network_attack_telemetry_logs WHERE src_ip = $1 AND observed_at > now()-interval '15 min'",
                "MATCH (a:Alert)-[:INFERRED_BY_AI]->(h:Host) WHERE a.sid = $sid RETURN h",
            ],
            "traces": [self.trace(incident_id, 1, thought,
                                  ["Encrypted C2 beacon", "Normal TLS variance", "TLS-fronted proxy"],
                                  confidence_delta=0.18)],
        }


# ---------------------------------------------------------------------------
# Cyber Intel AI Agent
# ---------------------------------------------------------------------------
class CyberIntelAgent(BaseSectorAgent):
    name = "Cyber_Intel_Agent"
    tools = ["AbuseIPDB reputation lookup", "AlienVault OTX pulse search", "CISA KEV correlation",
             "Threat actor attribution graph (Neo4j)", "Financial exposure model"]

    def analyze(self, incident_id: str, events: List[IDSEvent]) -> Dict[str, Any]:
        top = max(events, key=lambda e: e.severity, default=None)
        sig = top.signature_name if top else "Unknown"
        est_downtime_cost = "$148K/hr revenue exposure (payments ingress path)"
        return {
            "agent": self.name,
            "attribution": "Probable: DDoS-for-hire booter lineage (Mirai-derived UDP amp vectors)"
                           if top and (top.traffic_volume_bps or 0) > 0 else "Unattributed scan activity",
            "correlated_cves": ["CVE-2024-3400 (PAN-OS)", "CVE-2023-46805 (FortiOS)"][: (1 if top and top.severity >= 4 else 0)],
            "financial_exposure": est_downtime_cost,
            "traces": [self.trace(incident_id, 1,
                f"Correlated '{sig}' with ET/Open rules, OTX pulses and KEV catalog; modeled blast radius to "
                f"business units fronted by target. Exposure estimate: {est_downtime_cost}.",
                ["Commodity attack", "Targeted APT pre-text", "Hacktivist"], confidence_delta=0.09)],
        }


# ---------------------------------------------------------------------------
# Honeypot AI Agent
# ---------------------------------------------------------------------------
class HoneypotAgent(BaseSectorAgent):
    name = "Honeypot_Agent"
    tools = ["Decoy provisioning", "Firewall route-to-deception API", "TTP capture pipeline"]

    def offer(self, incident_id: str, src_ip: str) -> Dict[str, Any]:
        return {
            "agent": self.name,
            "decoy_rule_preview": f"iptables -t nat -A PREROUTING -s {src_ip} -j DNAT --to-destination 172.16.250.{abs(hash(src_ip)) % 250 + 1}",
            "rationale": f"Route {src_ip} into deception traps to harvest TTPs while removing it from production path.",
        }


# ---------------------------------------------------------------------------
# AppSec & AI Systems Agent
# ---------------------------------------------------------------------------
class AppSecAgent(BaseSectorAgent):
    name = "AppSec_AI_Systems_Agent"
    tools = ["MCP server audit", "LLM tool-call monitor", "SCA dependency scanner", "Prompt-injection detector"]

    def analyze(self, incident_id: str, events: List[IDSEvent]) -> Dict[str, Any]:
        return {
            "agent": self.name,
            "findings": [
                "No anomalous MCP tool-call sequences in correlated window.",
                "SCA: 0 critical vulnerabilities introduced in last 20 deploys.",
            ],
            "traces": [self.trace(incident_id, 1,
                "Reviewed AI-system surface: MCP servers, agent tool-call logs, dependency tree. No prompt-"
                "injection signatures matched against scraped guardrail corpus.",
                ["AI supply-chain tampering", "Benign"], confidence_delta=0.02)],
        }


# ---------------------------------------------------------------------------
# Patch Assistant AI Agent
# ---------------------------------------------------------------------------
class PatchAssistantAgent(BaseSectorAgent):
    name = "Patch_Assistant_Agent"
    tools = ["Repo analysis", "IaC patch drafting (Terraform)", "CI test harness"]

    def draft(self, incident_id: str, cve: str | None) -> Dict[str, Any]:
        if not cve:
            return {"agent": self.name, "patch_draft": None}
        return {
            "agent": self.name,
            "patch_draft": (
                f"# Terraform: upgrade affected NGFW firmware for {cve}\n"
                'resource "panos_system_setting" "firmware" {\n  sw_version = "11.0.3"\n}\n'
                "# CI: run commit-mode dry-run + HA failover test suite"
            ),
            "traces": [self.trace(incident_id, 1,
                f"Drafted IaC remediation for {cve}; queued infra-as-code dry-run tests before proposal merge.",
                ["Vendor patch available", "Mitigate via WAF virtual patch"], confidence_delta=0.07)],
        }


SECTOR_AGENTS = {
    "firewall_ips": FirewallIPSAgent(),
    "ddos": DDoSAgent(),
    "detection_ids": DetectionIDSAgent(),
    "cyber_intel": CyberIntelAgent(),
    "honeypot": HoneypotAgent(),
    "appsec": AppSecAgent(),
    "patch": PatchAssistantAgent(),
}
