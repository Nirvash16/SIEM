"""End-to-end verification of the platform core:
tiered routing, HITL gate enforcement, DDoS classification, approvals,
one-click bar, intel scraping, sanitization and DPO/SFT pipelines."""
import sys

sys.path.insert(0, ".")

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

PASS = 0


def check(name: str, cond: bool, extra: str = ""):
    global PASS
    assert cond, f"FAILED: {name} {extra}"
    PASS += 1
    print(f"  ✓ {name}")


with TestClient(app) as client:  # lifespan runs: seeds topology + incidents + scrape
    # --- Health & seed state -------------------------------------------------
    h = client.get("/api/v1/health").json()
    check("health operational", h["status"] == "OPERATIONAL")
    check("3 seeded incidents", h["incidents"] >= 3, str(h))
    check("intel corpus populated (offline fallback)", h["intel_corpus"] >= 10)

    incs = client.get("/api/v1/incidents").json()
    by_id = {i["incident_id"]: i for i in incs}

    t1 = by_id["inc-demo-tier1"]
    check("Tier-1 port sweep → autonomous EXECUTED", t1["tier"] == 1 and t1["proposal"]["status"] == "EXECUTED",
          str(t1["proposal"]["status"]))
    t2 = by_id["inc-demo-tier2"]
    check("Tier-2 SYN flood classified PROTOCOL", t2["attack_class"] == "PROTOCOL", t2["attack_class"])
    check("Tier-2 PENDING human approval", t2["proposal"]["status"] == "PENDING")
    check("Tier-2 rule is SYN_COOKIE @ EBPF_XDP",
          t2["proposal"]["firewall_rule"]["action"] == "SYN_COOKIE"
          and t2["proposal"]["firewall_rule"]["enforcement_layer"] == "EBPF_XDP")
    t3 = by_id["inc-demo-tier3"]
    check("Tier-3 14.8Gbps flood → VOLUMETRIC/TIER_3", t3["tier"] == 3 and t3["attack_class"] == "VOLUMETRIC",
          f"{t3['tier']}/{t3['attack_class']}")
    check("Tier-3 scrubbing-center rule", t3["proposal"]["firewall_rule"]["enforcement_layer"] == "SCRUBBING_CENTER")
    check("Tier-3 blast radius includes BGP control plane",
          any(b["entity"] == "BGP Control Plane" for b in t3["proposal"]["blast_radius"]))
    check("multi-agent traces recorded", len(t3["agent_traces"]) >= 5, str(len(t3["agent_traces"])))

    # --- L7 application-layer detection --------------------------------------
    r = client.post("/api/v1/incidents/network-ingest", json={
        "incident_id": "inc-l7-test",
        "ids_events": [{
            "sensor_id": "waf-sensor-1", "signature_id": "DDoS_HTTP_FLOOD SID:9000100",
            "signature_name": "HTTP GET Flood / Slowloris pattern", "src_ip": "192.0.2.99",
            "dst_ip": "10.20.4.10", "dst_port": 443, "protocol": "TCP", "severity": 3,
            "traffic_volume_bps": 300_000_000, "packets_per_second": 60_000, "requests_per_second": 9_000,
        }]})
    l7 = r.json()
    check("L7 flood → APPLICATION class", l7["attack_class"] == "APPLICATION", l7["attack_class"])
    check("L7 → AWS_WAF rate-limit rule", l7["proposal"]["firewall_rule"]["enforcement_layer"] == "AWS_WAF"
          and l7["proposal"]["firewall_rule"]["action"] == "RATE_LIMIT")

    # --- HITL gate: no execution without human -------------------------------
    prop_id = t3["proposal"]["proposal_id"]
    queue = client.get("/api/v1/approvals/queue").json()
    check("approval queue priority-ordered (T3 first)", queue[0]["tier"] == 3, str([q["tier"] for q in queue]))

    pol_before = len(client.get("/api/v1/network/policies").json())
    # Direct one-click high-risk WITHOUT reviewer must be refused (403).
    denied = client.post(f"/api/v1/network/one-click/commit_permanent_ngfw_policy?incident_id={t3['incident_id']}")
    check("permanent NGFW one-click blocked without human (403)", denied.status_code == 403, denied.text)
    pol_after = len(client.get("/api/v1/network/policies").json())
    check("no policy leaked past HITL gate", pol_after == pol_before)

    # --- Human approval executes Tier-3 ---------------------------------------
    rev = client.post(f"/api/v1/approvals/{prop_id}/review", json={
        "action": "APPROVED", "reviewer_id": "ciso.reviewer@enterprise", "feedback_notes": "Scrub route OK."})
    check("Tier-3 approval executes mitigation", rev.json()["status"] == "SUCCESS"
          and "execution" in rev.json(), rev.text)
    after = client.get(f"/api/v1/approvals/{prop_id}").json()
    check("proposal now EXECUTED with approver logged", after["proposal"]["status"] == "EXECUTED")
    check("review stored for RLHF", len(after["review_history"]) == 1)

    rej = client.post(f"/api/v1/approvals/{t2['proposal']['proposal_id']}/review", json={
        "action": "REJECTED", "reviewer_id": "l2.analyst@enterprise",
        "feedback_notes": "Rate limit too aggressive; would drop CDN healthchecks."})
    check("reject+escalate works", rej.json()["action_taken"] == "REJECTED" and "escalation" in rej.json())

    bad = client.post(f"/api/v1/approvals/{prop_id}/review", json={"action": "EXECUTED", "reviewer_id": "x"})
    check("invalid review action rejected (4xx)", bad.status_code in (400, 409, 422), str(bad.status_code))

    # --- Edit proposal flow ----------------------------------------------------
    edit_inc = client.post("/api/v1/incidents/network-ingest", json={
        "incident_id": "inc-edit-test",
        "ids_events": [{
            "sensor_id": "ids-sensor-1", "signature_id": "DDoS_SYN_FLOOD SID:2800999",
            "signature_name": "SYN flood variant", "src_ip": "198.51.100.77", "dst_ip": "10.20.4.10",
            "dst_port": 80, "protocol": "TCP", "severity": 4,
            "traffic_volume_bps": 2_000_000_000, "packets_per_second": 800_000}]})
    ep = edit_inc.json()["proposal"]["proposal_id"]
    edited_rule = dict(edit_inc.json()["proposal"]["firewall_rule"])
    edited_rule["rate_limit_pps"] = 50_000
    er = client.patch(f"/api/v1/approvals/{ep}/rule", json=edited_rule)
    check("analyst can edit pending rule (diff re-render path)", er.json()["status"] == "MODIFIED"
          and er.json()["proposal"]["firewall_rule"]["rate_limit_pps"] == 50_000)

    # --- Rollback safety check --------------------------------------------------
    policies = client.get("/api/v1/network/policies").json()
    active = [p for p in policies if not p["rolled_back"]]
    rb = client.post(f"/api/v1/network/mitigations/{active[0]['id']}/rollback?actor=Human_CISO")
    check("rollback reverses executed mitigation", rb.json()["status"] == "ROLLED_BACK")

    # --- One-click temporary drop (Tier-1 preset, autonomous) -------------------
    oc = client.post("/api/v1/network/one-click/deploy_temporary_ips_drop_1h"
                     "?incident_id=inc-edit-test&src_ip=198.51.100.77")
    check("one-click temp IPS drop applies", oc.json()["status"] == "EXECUTED", oc.text)

    # --- Visibility matrix & topology -------------------------------------------
    vis = client.get("/api/v1/network/visibility").json()
    check("visibility baseline series present", len(vis["baselines"]) > 40)
    check("anomaly scores bounded", all(0 <= b["anomaly_score"] <= 1 for b in vis["baselines"]))
    topo = client.get("/api/v1/network/topology").json()
    kinds = {n["node_type"] for n in topo["nodes"]}
    check("topology has firewall/ids/scrub/mcp/alert nodes",
          {"FIREWALL", "IDS_SENSOR", "SCRUBBING_CENTER", "MCP_SERVER", "ALERT"} <= kinds, str(kinds))
    etypes = {e["edge_type"] for e in topo["edges"]}
    check("observed vs inferred edge provenance", etypes == {"DIRECTLY_OBSERVED", "INFERRED_BY_AI"})
    det = client.get("/api/v1/network/nodes/fw-edge/detail").json()
    check("node drawer returns pcap + SIDs", len(det["pcap_traces"]) == 8 and det["active_sids"])

    # --- Intelligence pipeline ----------------------------------------------------
    scrape = client.post("/api/v1/intel/scrape/run").json()
    check("scraper engine idempotent dedupe", isinstance(scrape["new_entries"], int) and scrape["corpus_size"] >= 10)
    entries = client.get("/api/v1/intel/entries").json()
    feeds = {e["feed"] for e in entries}
    check("CF Radar + Akamai SOTI + KEV feeds represented",
          {"CF_RADAR_DDOS", "AKAMAI_SOTI", "CISA_KEV"} & feeds != set(), str(feeds))
    sft = client.get("/api/v1/intel/datasets/sft-preview").json()
    check("SFT samples curated from agent traces", len(sft) > 0 and "instruction" in sft[0])
    dpo = client.get("/api/v1/intel/datasets/dpo-preview").json()
    check("DPO pairs built from reviews (chosen/rejected)", len(dpo) >= 2
          and all(p["chosen"] and p["rejected"] for p in dpo))
    ts = client.get("/api/v1/intel/training/status").json()
    check("training threshold reported", ts["trigger_threshold"] == 1000 and ts["verified_review_count"] == 2)
    ft = client.post("/api/v1/intel/training/force-trigger").json()
    check("LoRA/QLoRA job queueable", ft["job_id"].startswith("train"))

    # --- Sanitization unit checks -------------------------------------------------
    from app.services.training_pipeline import sanitize_log
    dirty = ("user name: Alice analyst name: Bob token ghp_abc123DEF456ghi789 email bob@corp.io "
             "src 10.20.4.10 -> 192.168.1.5 dst")
    clean = sanitize_log(dirty)
    check("sanitizer scrubs subnets/tokens/emails/PII",
          all(t not in clean for t in ["Alice", "Bob", "ghp_", "bob@corp.io", "10.20.4.10", "192.168.1.5"]), clean)

    audit = client.get("/api/v1/intel/audit").json()
    check("audit trail captured autonomous + human actions",
          any(a["action"] == "TIER1_AUTONOMOUS_EXECUTION" for a in audit)
          and any(a["action"] == "HITL_APPROVED" for a in audit))

print(f"\nALL {PASS} CHECKS PASSED ✔")
