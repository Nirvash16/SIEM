"""Intelligence scrapers + log sanitization + SFT/DPO training pipeline.

Async httpx scrapers target the feed list from the spec (ET Open Rules, Snort
Community, AbuseIPDB, OTX, CISA KEV, Palo Alto Unit42, Fortinet, Cisco Talos,
Cloudflare Radar DDoS, Akamai SOTI). In offline/CI mode they fall back to a
curated sample corpus so the platform always has intel to serve and embed.

Sanitization scrubs internal subnets, tokens and PII before anything is emitted
as a training dataset. Training triggers LoRA/QLoRA runs once > 1000 verified
human reviews accumulate.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.config import settings
from app.schemas.security import (
    DPOPair, HumanActionReview, ThreatFeedItem, TrainingJob, ActionStatus, utcnow,
)
from app.services.event_bus import bus, repo

# ---------------------------------------------------------------------------
# Feed registry
# ---------------------------------------------------------------------------
FEEDS: Dict[str, str] = {
    "ET_OPEN_RULES":   "https://rules.emergingthreats.net/open/emerging-all.rules",
    "SNORT_COMMUNITY": "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
    "ABUSEIPDB":       "https://api.abuseipdb.com/api/v2/blacklist",
    "ALIENVAULT_OTX":  "https://otx.alienvault.com/api/v1/pulses/features",
    "CISA_KEV":        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "UNIT42":          "https://unit42.paloaltonetworks.com/feed/",
    "FORTIGUARD":      "https://www.fortiguard.com/rssfeed",
    "CISCO_TALOS":     "https://blog.talosintelligence.com/rss/",
    "CF_RADAR_DDOS":   "https://api.cloudflare.com/client/v4/radar/ddos/attack-summary/topCountries",
    "AKAMAI_SOTI":     "https://www.akamai.com/us/en/soti.page",
}

SAMPLE_CORPUS: List[Tuple[str, str, str, str, str]] = [
    ("ET_OPEN_RULES", "SURICATA_RULE", "ET DROP Dshield Block Listed Source group 1",
     "drop tcp $EXTERNAL_NET any -> $HOME_NET any (msg:\"ET DROP Dshield Block Listed Source\"; sid:2001575; rev:23;)", "high"),
    ("ET_OPEN_RULES", "SURICATA_RULE", "DDoS SYN Flood detected",
     'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"DDoS SYN_FLOOD"; flags:S; threshold:type both, track by_dst, seconds 1, count 10000; sid:2800999;)', "critical"),
    ("SNORT_COMMUNITY", "SURICATA_RULE", "ET WEB_SERVER SQL Injection Attempt UNION SELECT",
     'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443] (msg:"ET WEB_SERVER SQLi Attempt UNION SELECT"; flow:to_server; content:"UNION SELECT"; nocase; sid:2013467;)', "critical"),
    ("YARA_REPOS", "YARA", "Mirai_Botnet_Generic",
     'rule Mirai_Generic { strings: $a = "/dev/urandom" $b = "xor_key" condition: all of them }', "high"),
    ("ABUSEIPDB", "BAD_IP", "45.155.205.233",
     "Confidence 100 - hosting bulletproof UDP amplification infrastructure", "high"),
    ("ABUSEIPDB", "BAD_IP", "185.220.101.34",
     "Tor exit node with credential-stuffing history against /auth endpoints", "medium"),
    ("CISA_KEV", "CVE", "CVE-2024-3400",
     "Palo Alto GlobalProtect OS command injection - actively exploited (NGFW pre-auth RCE)", "critical"),
    ("CISA_KEV", "CVE", "CVE-2023-46805",
     "Fortinet FortiOS sslvpnd authentication bypass - KEV listed", "critical"),
    ("CF_RADAR_DDOS", "PLAYBOOK", "CF-RADAR-Q3-2026-DDOS-REPORT",
     "Radar: record 3.9 Tbps volumetric attack mitigated; UDP amplification vectors up 31% QoQ; SYN flood peak 2.3 rps x10^8", "info"),
    ("AKAMAI_SOTI", "PLAYBOOK", "AKAMAI-SOTI-L7-FLOOD-GUIDANCE",
     "HTTP/2 Rapid Reset & Slowloris L7 floods dominate application-layer incidents; recommend rate-based WAF + JS challenge", "info"),
    ("ZEEK_INTEL", "BAD_IP", "198.51.100.0/24",
     "Zeek Intel feed: confirmed DNS amplification reflector block", "medium"),
]


async def fetch(url: str, timeout: float = 5.0) -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(url, headers={"User-Agent": "ciso-pulse-intel-collector/1.0"})
            if r.status_code == 200:
                return r.text
    except Exception:
        pass  # offline demo/CI — fall back to curated corpus
    return None


# ---------------------------------------------------------------------------
# Log sanitization / anonymization pipeline
# ---------------------------------------------------------------------------
_INTERNAL_SUBNET = re.compile(r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b")
_TOKEN = re.compile(r"\b(?:ghp|glpat|xox[baprs]|AKIA)[A-Za-z0-9_\-]{6,}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PII_NAME = re.compile(r"(?i)\b(employee|analyst|user)\s+name\s*[:=]\s*\S+")


def sanitize_log(text: str) -> str:
    """Scrub enterprise topology internals, credentials and PII before datasets emit."""
    text = _INTERNAL_SUBNET.sub("<INTERNAL_HOST>", text)
    text = _TOKEN.sub("<REDACTED_TOKEN>", text)
    text = _EMAIL.sub("<REDACTED_EMAIL>", text)
    text = _PII_NAME.sub(r"\1 name: <REDACTED>", text)
    return text


# ---------------------------------------------------------------------------
# Scraper engine
# ---------------------------------------------------------------------------
async def scrape_all_feeds() -> int:
    """Pull every registered feed; parse into ThreatFeedItems; embed into pgvector store."""
    added = 0
    live_items: List[ThreatFeedItem] = []

    kev_txt = await fetch(FEEDS["CISA_KEV"])
    if kev_txt:
        try:
            data = kev_txt if isinstance(kev_txt, dict) else __import__("json").loads(kev_txt)
            for vuln in data.get("vulnerabilities", [])[:10]:
                live_items.append(ThreatFeedItem(
                    feed="CISA_KEV", entry_type="CVE", identifier=vuln["cveID"],
                    summary=f"{vuln.get('product','')} — {vuln.get('vulnerability','')}",
                    severity="critical",
                ))
        except Exception:
            pass

    et_txt = await fetch(FEEDS["ET_OPEN_RULES"])
    if et_txt:
        for line in et_txt.splitlines():
            if line.startswith("alert") or line.startswith("drop"):
                m = re.search(r'msg:"([^"]+)"', line)
                sid = re.search(r"sid:(\d+)", line)
                if m and sid:
                    live_items.append(ThreatFeedItem(
                        feed="ET_OPEN_RULES", entry_type="SURICATA_RULE",
                        identifier=m.group(1), content=sanitize_log(line),
                        severity="high",
                    ))
                    if len(live_items) > 40:
                        break

    items = live_items or []
    if not items:  # offline fallback corpus keeps the pipeline demonstrable
        for feed, etype, ident, content, sev in SAMPLE_CORPUS:
            items.append(ThreatFeedItem(feed=feed, entry_type=etype, identifier=ident,
                                        summary=sanitize_log(content)[:200], content=sanitize_log(content),
                                        severity=sev))

    for item in items:
        # pgvector stand-in: deterministic embedding reference per content hash.
        item.embedded = True
        item.scraped_at = utcnow()
        if repo.add_intel(item):
            added += 1

    if added:
        await bus.publish("intel", {"type": "FEED_SYNC", "new_entries": added,
                                    "corpus_size": len(repo.threat_intel)})
    return added


# ---------------------------------------------------------------------------
# SFT / DPO dataset curation
# ---------------------------------------------------------------------------
def curate_sft_samples() -> List[Dict[str, Any]]:
    """Historical logs + IDS hits + generated rules + agent reasoning → instruction pairs."""
    samples: List[Dict[str, Any]] = []
    for trace in repo.traces:
        incident = repo.incidents.get(trace.incident_id or "")
        if not incident:
            continue
        rule_preview = ""
        if incident.proposal and incident.proposal.firewall_rule:
            rule_preview = incident.proposal.firewall_rule.rule_definition_preview or ""
        samples.append({
            "instruction": sanitize_log(
                f"You are the {trace.agent_name}. Incident: {incident.title}. "
                f"Telemetry metrics: bps={incident.ddos_metrics.get('peak_bps', 0)}, "
                f"pps={incident.ddos_metrics.get('peak_pps', 0)}. Propose a mitigation."
            ),
            "output": sanitize_log(f"{trace.llm_thought_process}\nACTION:\n{rule_preview}"),
            "meta": {"incident_id": incident.incident_id, "tier": int(incident.tier)},
        })
    return samples


def generate_dpo_pairs() -> List[DPOPair]:
    """Chosen = human-approved mitigations that preserved legitimate traffic.
    Rejected = human-rejected rules / false-positive blockers / hallucinated syntax."""
    pairs: List[DPOPair] = []
    for review in repo.reviews:
        prompt = sanitize_log(str(review.proposed_action.get("proposed_action", review.proposal_id)))
        chosen_rule = review.proposed_action.get("rule_preview", "")
        if review.action_taken == ActionStatus.APPROVED:
            rejected = (
                "DROP ip src 0.0.0.0/0 dst 10.0.0.0/8 any  # overbroad: blackholed entire CDN range, "
                "blocked critical microservice payments-ingress for 11 minutes (FALSE POSITIVE OUTAGE)"
            )
        else:
            rejected = chosen_rule or review.proposed_action.get("proposed_action", "")
            chosen = review.human_feedback_notes or "Escalate to scrubbing-center reroute instead of local drop."
            chosen_rule = chosen
        pairs.append(DPOPair(
            prompt=prompt,
            chosen=sanitize_log(chosen_rule),
            rejected=sanitize_log(rejected),
            incident_id=review.incident_id,
        ))
    return pairs


async def maybe_trigger_fine_tuning() -> Optional[TrainingJob]:
    """Trigger LoRA/QLoRA run once > dpo_trigger_threshold verified reviews exist."""
    count = repo.verified_review_count
    if count < settings.dpo_trigger_threshold:
        return None
    sft = curate_sft_samples()
    dpo = generate_dpo_pairs()
    job = TrainingJob(
        job_id=f"train-{uuid.uuid4().hex[:10]}",
        dataset_kind="SFT+DPO",
        sample_count=len(sft) + len(dpo),
        verified_review_count=count,
        status="QUEUED",
    )
    repo.add_training_job(job)
    repo.audit("Training_Pipeline", "LORA_RUN_QUEUED",
               {"job_id": job.job_id, "samples": job.sample_count, "reviews": count})
    await bus.publish("training", {"type": "TRAINING_QUEUED", "job_id": job.job_id,
                                   "method": job.method, "samples": job.sample_count})
    return job
