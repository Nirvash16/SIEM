"""Seed data: realistic topology, traffic baselines and demo incidents so the
Cyber Command UI renders a populated command center on first boot."""
from __future__ import annotations

import math
import random
from datetime import timedelta

from app.agents.ciso_agent import ciso_agent
from app.schemas.security import (
    AttackClass, BaselineBucket, IncidentStatus, TopologyEdge, TopologyNode, utcnow,
)
from app.services.event_bus import bus, repo


def seed_topology() -> None:
    nodes = [
        TopologyNode(id="attacker-1", label="203.0.113.66\n(Booter C2)", node_type="ALERT", status="adversarial", x=40, y=180,
                     metrics={"bps": 14_800_000_000, "pps": 9_200_000}),
        TopologyNode(id="attacker-2", label="198.51.100.24\n(DNS Amp Reflectors)", node_type="ALERT", status="adversarial", x=40, y=360,
                     metrics={"bps": 2_100_000_000, "pps": 640_000}),
        TopologyNode(id="scrub-a", label="Scrubbing Center A\n(Cloudflare/Akamai POP)", node_type="SCRUBBING_CENTER", status="standby", x=250, y=90,
                     metrics={"capacity_gbps": 400, "clean_bps": 0}),
        TopologyNode(id="fw-edge", label="Perimeter NGFW\nPA-5400 Cluster", node_type="FIREWALL", status="mitigating", x=250, y=300,
                     metrics={"session_util_pct": 71, "drops_pps": 880_000}),
        TopologyNode(id="ids-sensor-1", label="IDS Sensor dc1-core\n(Suricata/eBPF)", node_type="IDS_SENSOR", status="healthy", x=250, y=480,
                     metrics={"alerts_15m": 412}),
        TopologyNode(id="vip-payments", label="payments-ingress VIP\n10.20.4.10", node_type="HOST", status="under_attack", x=470, y=220,
                     metrics={"bps_in": 16_900_000_000, "rps": 7_400, "latency_p99_ms": 812}),
        TopologyNode(id="svc-checkout", label="checkout-web\n(microservice)", node_type="HOST", status="degraded", x=650, y=160,
                     metrics={"error_rate_pct": 4.2}),
        TopologyNode(id="mcp-gw", label="MCP Security Gateway\n(agent tool plane)", node_type="MCP_SERVER", status="healthy", x=650, y=420,
                     metrics={"tool_calls_1h": 1_204, "prompt_injections_blocked": 3}),
        TopologyNode(id="identity-ciso", label="Human CISO\n(approval authority)", node_type="IDENTITY", status="online", x=470, y=520),
    ]
    edges = [
        TopologyEdge(id="e1", source="attacker-1", target="fw-edge", edge_type="DIRECTLY_OBSERVED",
                     label="UDP/ICMP flood 14.8 Gbps", throughput_bps=14_800_000_000),
        TopologyEdge(id="e2", source="attacker-2", target="fw-edge", edge_type="DIRECTLY_OBSERVED",
                     label="DNS amp 640 kpps", throughput_bps=2_100_000_000),
        TopologyEdge(id="e3", source="fw-edge", target="vip-payments", edge_type="DIRECTLY_OBSERVED",
                     label="forwarded 1.2 Gbps", throughput_bps=1_200_000_000),
        TopologyEdge(id="e4", source="fw-edge", target="scrub-a", edge_type="DIRECTLY_OBSERVED",
                     label="flowspec redirect", throughput_bps=14_000_000_000),
        TopologyEdge(id="e5", source="ids-sensor-1", target="fw-edge", edge_type="DIRECTLY_OBSERVED",
                     label="alert stream"),
        TopologyEdge(id="e6", source="attacker-1", target="svc-checkout", edge_type="INFERRED_BY_AI",
                     label="AI path: L7 pivot via HTTP/2 reset (conf 0.78)"),
        TopologyEdge(id="e7", source="attacker-2", target="mcp-gw", edge_type="INFERRED_BY_AI",
                     label="AI path: JA4 cluster → tool-abuse attempt (conf 0.61)"),
        TopologyEdge(id="e8", source="identity-ciso", target="fw-edge", edge_type="INFERRED_BY_AI",
                     label="HITL approval channel"),
    ]
    for n in nodes:
        repo.upsert_node(n)
    for e in edges:
        repo.upsert_edge(e)


def seed_baselines() -> None:
    """60 minutes of baseline vs actual bps with an attack ramp in the last third."""
    now = utcnow()
    points = []
    for i in range(60):
        ts = now - timedelta(minutes=59 - i)
        expected = 2_000_000_000 + int(400_000_000 * math.sin(i / 8))          # diurnal wave ~2 Gbps
        if i < 40:
            actual = expected + random.randint(-120_000_000, 160_000_000)
            score = round(min(0.25, abs(actual - expected) / 2_000_000_000), 3)
        elif i < 48:
            spike = (i - 39) * 900_000_000
            actual = expected + spike + random.randint(0, 100_000_000)
            score = round(min(0.9, 0.3 + (i - 40) * 0.08), 3)
        else:
            decay = max(0, (59 - i) * 700_000_000)
            actual = expected + decay + random.randint(0, 200_000_000)
            score = round(max(0.15, (59 - i) * 0.07), 3)
        points.append(BaselineBucket(ts=ts, expected_bps=int(expected), actual_bps=int(actual), anomaly_score=score))
    repo.baselines.clear()
    repo.baselines.extend(points)


async def seed_demo_incidents() -> None:
    """One incident per tier to populate dossier view + approval queue."""
    scenarios = [
        # Tier 1 — known bad IP scan (autonomous temporary drop)
        ("inc-demo-tier1", [{
            "sensor_id": "ids-sensor-1", "signature_id": "ET SCAN Nmap Xmas Scan SID:2001575",
            "signature_name": "ET SCAN Basic Port Sweep", "src_ip": "192.0.2.19", "dst_ip": "10.20.4.10",
            "dst_port": 22, "protocol": "TCP", "severity": 1,
            "traffic_volume_bps": 120_000, "packets_per_second": 800,
            "raw_payload": "hex:16 03 01 00 a2 | ascii: TLS handshake noise",
        }]),
        # Tier 2 — multi-vector SYN flood (agent-assisted, needs copilot review)
        ("inc-demo-tier2", [{
            "sensor_id": "ids-sensor-1", "signature_id": "DDoS_SYN_FLOOD SID:2800999",
            "signature_name": "Protocol SYN Flood toward payments ingress", "src_ip": "198.51.100.24",
            "dst_ip": "10.20.4.10", "dst_port": 443, "protocol": "TCP", "severity": 4,
            "traffic_volume_bps": 3_400_000_000, "packets_per_second": 1_900_000,
            "log_type": "DDOS_VOLUME_SPIKE",
        }]),
        # Tier 3 — massive volumetric + SQLi combo (CISO sign-off card)
        ("inc-demo-tier3", [
            {"sensor_id": "ids-sensor-1", "signature_id": "DDoS UDP_AMPLIFICATION SID:2801412",
             "signature_name": "Volumetric UDP/NTP amplification flood", "src_ip": "203.0.113.66",
             "dst_ip": "10.20.4.10", "dst_port": 53, "protocol": "UDP", "severity": 5,
             "traffic_volume_bps": 14_800_000_000, "packets_per_second": 9_200_000,
             "log_type": "DDOS_VOLUME_SPIKE"},
            {"sensor_id": "ids-sensor-2", "signature_id": "ET WEB_SERVER SQLi Attempt SID:2013467",
             "signature_name": "ET WEB_SERVER SQLi Attempt UNION SELECT (coordinated)", "src_ip": "203.0.113.66",
             "dst_ip": "10.20.4.10", "dst_port": 443, "protocol": "TCP", "severity": 4,
             "traffic_volume_bps": 90_000_000, "packets_per_second": 40_000, "requests_per_second": 6_200,
             "raw_payload": "ascii:' UNION SELECT username,password FROM creds--"},
        ]),
    ]
    for incident_id, events in scenarios:
        dossier = await ciso_agent.evaluate_incident(incident_id, events)
        repo.save_incident(dossier)
        for t in dossier.agent_traces:
            repo.add_trace(t)
        if dossier.proposal:
            repo.save_proposal(dossier.proposal)
            if dossier.tier == 1:
                from app.services.mitigation_executor import execute_mitigation
                result = await execute_mitigation(dossier.proposal, approved_by_human=None,
                                                  applied_by_agent="Firewall_IPS_Agent")
                repo.audit("CISO_Agent", "TIER1_AUTONOMOUS_EXECUTION",
                           {"incident_id": incident_id, "change_id": result["change_id"]})
                dossier.status = IncidentStatus.RESOLVED
        await bus.publish("incidents", {"type": "INCIDENT_SEEDED", "incident_id": incident_id,
                                       "tier": int(dossier.tier)})
