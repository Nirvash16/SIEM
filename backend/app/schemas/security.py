"""Pydantic v2 schemas & enums for the IDS/IPS/Firewall/DDoS core API."""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# ENUMS
# ---------------------------------------------------------------------------
class TierLevel(int, enum.Enum):
    TIER_1 = 1  # Easy/Auto-solve (temporary IP drop, basic rate limiting)
    TIER_2 = 2  # Medium/Assisted (dynamic IPS signature creation, L7 DDoS mitigation)
    TIER_3 = 3  # Hard/CISO Approval (persistent NGFW ACL rewrite, BGP blackholing, scrubbing)


class ActionStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"


class IncidentStatus(str, enum.Enum):
    INGESTED = "Ingested"
    INVESTIGATING = "Investigating"
    PENDING_APPROVAL = "Pending_Approval"
    RESOLVED = "Resolved"


class Sector(str, enum.Enum):
    FIREWALL_IDS_IPS_DDOS = "Firewall_IDS_IPS_DDOS"
    DETECTION_IDS = "Detection_IDS"
    DDOS_MITIGATION = "DDoS_Mitigation"
    PATCH_ASSISTANT = "Patch_Assistant"
    CYBER_INTEL = "Cyber_Intel"
    HONEYPOT = "Honeypot"
    APPSEC_AI_SYSTEMS = "AppSec_AI_Systems"


class EnforcementLayer(str, enum.Enum):
    EBPF_XDP = "EBPF_XDP"
    IPTABLES = "IPTABLES"
    NGFW_API = "NGFW_API"
    AWS_WAF = "AWS_WAF"
    CLOUDFLARE_WAF = "CLOUDFLARE_WAF"
    BGP_FLOWSPEC = "BGP_FLOWSPEC"
    SCRUBBING_CENTER = "SCRUBBING_CENTER"


class RuleAction(str, enum.Enum):
    DROP = "DROP"
    REJECT = "REJECT"
    ALLOW = "ALLOW"
    RATE_LIMIT = "RATE_LIMIT"
    SYN_COOKIE = "SYN_COOKIE"
    SCRUB_REDIRECT = "SCRUB_REDIRECT"
    HONEYPOT_ROUTE = "HONEYPOT_ROUTE"


class LogType(str, enum.Enum):
    IDS_ALERT = "IDS_ALERT"
    IPS_DROP = "IPS_DROP"
    FIREWALL_DENY = "FIREWALL_DENY"
    PCAP_TRACE = "PCAP_TRACE"
    DDOS_VOLUME_SPIKE = "DDOS_VOLUME_SPIKE"
    NETFLOW_BASELINE = "NETFLOW_BASELINE"
    SFLOW_SAMPLE = "SFLOW_SAMPLE"
    WAF_LOG = "WAF_LOG"


class AttackClass(str, enum.Enum):
    NONE = "NONE"
    VOLUMETRIC = "VOLUMETRIC"          # UDP/ICMP floods
    PROTOCOL = "PROTOCOL"              # SYN floods, DNS amplification
    APPLICATION = "APPLICATION"        # HTTP GET/POST floods, Slowloris


# ---------------------------------------------------------------------------
# TELEMETRY / IDS EVENTS
# ---------------------------------------------------------------------------
class IDSEvent(BaseModel):
    sensor_id: str
    signature_id: str
    signature_name: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str = "TCP"
    severity: int = Field(ge=1, le=5)
    observed_at: datetime = Field(default_factory=utcnow)
    # --- DDoS Visibility Metrics (Comprehensive Network Visibility tenet) ---
    traffic_volume_bps: Optional[int] = Field(None, description="Bits per second observed at sensor")
    packets_per_second: Optional[int] = Field(None, description="Packets per second observed at sensor")
    requests_per_second: Optional[int] = Field(None, description="L7 request rate (HTTP flood detection)")
    raw_payload: Optional[str] = Field(None, description="Hex/ASCII payload excerpt")
    log_type: LogType = LogType.IDS_ALERT

    @field_validator("traffic_volume_bps", "packets_per_second", "requests_per_second")
    @classmethod
    def _non_negative(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 0:
            raise ValueError("telemetry rates must be non-negative")
        return v


class TelemetryLog(IDSEvent):
    """Persisted form of a telemetry record (mirrors network_attack_telemetry_logs)."""
    id: str = ""
    incident_id: Optional[str] = None
    source_system: str = "Suricata"
    parsed_entities: Dict[str, Any] = Field(default_factory=dict)
    is_adversarial_pattern: bool = False


# ---------------------------------------------------------------------------
# FIREWALL / IPS / DDOS RULES
# ---------------------------------------------------------------------------
class FirewallRuleProposal(BaseModel):
    rule_id: str
    action: RuleAction
    src_ip_cidr: str
    dst_ip_cidr: str
    dst_port: int
    protocol: str = "TCP"
    enforcement_layer: EnforcementLayer
    rate_limit_pps: Optional[int] = None
    suricata_rule_sid: Optional[int] = None
    duration_seconds: Optional[int] = Field(
        None, description="None = Permanent. Temporary mitigations auto-expire."
    )
    rule_definition_preview: Optional[str] = Field(
        None, description="Rendered Suricata/eBPF/WAF snippet for the diff viewer"
    )


class FirewallPolicyChange(BaseModel):
    """Mirrors the firewall_policy_changes table."""
    id: str = ""
    incident_id: Optional[str] = None
    device_id: str
    rule_type: RuleAction
    rule_definition: Dict[str, Any]
    enforcement_layer: EnforcementLayer
    applied_by_agent: str
    approved_by_human: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=utcnow)
    rolled_back: bool = False


# ---------------------------------------------------------------------------
# ACTION PROPOSALS & HITL
# ---------------------------------------------------------------------------
class BlastRadiusNode(BaseModel):
    entity: str
    entity_type: str  # HOST | SERVICE | FIREWALL | CDN | BUSINESS_UNIT
    impact: str       # LOW | MEDIUM | HIGH | CRITICAL


class ActionProposal(BaseModel):
    proposal_id: str
    incident_id: str
    target_entity: str
    proposed_action: str
    tier: TierLevel = TierLevel.TIER_2
    attack_class: AttackClass = AttackClass.NONE
    firewall_rule: Optional[FirewallRuleProposal] = None
    expected_security_benefit: str
    business_impact_analysis: str
    downstream_dependencies: List[str] = Field(default_factory=list)
    rollback_steps: List[str] = Field(default_factory=list)
    required_approvers: List[str] = Field(default_factory=list)
    blast_radius: List[BlastRadiusNode] = Field(default_factory=list)
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _permanent_high_risk_needs_rollback(self) -> "ActionProposal":
        # Strict rule: permanent / high-blast-radius actions must ship with rollback steps.
        if self.firewall_rule and self.firewall_rule.duration_seconds is None:
            if not self.rollback_steps:
                raise ValueError(
                    "Permanent policy rewrites require explicit rollback steps (HITL safety check)"
                )
        return self


class HumanActionReview(BaseModel):
    """Mirrors human_action_reviews — also feeds the RLHF/DPO pipeline."""
    id: str = ""
    incident_id: Optional[str] = None
    proposal_id: str
    proposed_action: Dict[str, Any]
    business_impact_analysis: Dict[str, Any] = Field(default_factory=dict)
    action_taken: ActionStatus
    reviewer_id: str
    human_feedback_notes: Optional[str] = None
    reviewed_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# AGENT TRACES
# ---------------------------------------------------------------------------
class AgentDecisionTrace(BaseModel):
    id: str = ""
    incident_id: Optional[str] = None
    agent_name: str
    step_number: int
    prompt_context: Dict[str, Any] = Field(default_factory=dict)
    llm_thought_process: str
    tool_calls_executed: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses_evaluated: List[str] = Field(default_factory=list)
    confidence_delta: Optional[float] = None
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# INCIDENT DOSSIER
# ---------------------------------------------------------------------------
class IncidentDossier(BaseModel):
    incident_id: str
    title: str
    tier: TierLevel
    sector: str
    status: IncidentStatus = IncidentStatus.INVESTIGATING
    summary: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    attack_class: AttackClass = AttackClass.NONE
    ddos_metrics: Dict[str, Any] = Field(default_factory=dict)
    ids_events: List[IDSEvent] = Field(default_factory=list)
    queries_executed: List[str] = Field(default_factory=list)
    data_gaps: List[str] = Field(default_factory=list)
    agent_traces: List[AgentDecisionTrace] = Field(default_factory=list)
    proposal: Optional[ActionProposal] = None
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# VISIBILITY / TOPOLOGY / TRAINING
# ---------------------------------------------------------------------------
class TopologyNode(BaseModel):
    id: str
    label: str
    node_type: str  # IDENTITY | HOST | FIREWALL | IDS_SENSOR | SCRUBBING_CENTER | MCP_SERVER | ALERT
    status: str = "healthy"
    metrics: Dict[str, Any] = Field(default_factory=dict)
    x: float = 0.0
    y: float = 0.0


class TopologyEdge(BaseModel):
    id: str
    source: str
    target: str
    edge_type: str  # DIRECTLY_OBSERVED | INFERRED_BY_AI
    label: Optional[str] = None
    throughput_bps: Optional[int] = None


class TopologyGraph(BaseModel):
    nodes: List[TopologyNode] = Field(default_factory=list)
    edges: List[TopologyEdge] = Field(default_factory=list)


class BaselineBucket(BaseModel):
    ts: datetime
    expected_bps: int
    actual_bps: int
    anomaly_score: float = Field(ge=0.0, le=1.0)


class VisibilitySnapshot(BaseModel):
    """Comprehensive Network Visibility dashboard payload."""
    generated_at: datetime = Field(default_factory=utcnow)
    total_ingress_bps: int = 0
    total_pps: int = 0
    active_flows: int = 0
    attack_breakdown: Dict[str, int] = Field(default_factory=dict)  # volumetric/protocol/app counts
    baselines: List[BaselineBucket] = Field(default_factory=list)
    top_talkers: List[Dict[str, Any]] = Field(default_factory=list)
    sensors_online: int = 0
    sensors_total: int = 0


class ThreatFeedItem(BaseModel):
    feed: str                 # ET_OPEN_RULES | SNORT_COMMUNITY | ABUSEIPDB | CISA_KEV | CF_RADAR ...
    entry_type: str           # SURICATA_RULE | YARA | CVE | BAD_IP | PLAYBOOK
    identifier: str
    summary: str
    severity: str = "medium"
    scraped_at: datetime = Field(default_factory=utcnow)
    embedded: bool = False    # ingested into pgvector


class TrainingJob(BaseModel):
    job_id: str
    dataset_kind: str         # SFT | DPO
    sample_count: int
    verified_review_count: int
    base_model: str = "llama-3.1-8b-instruct"
    method: str = "LoRA/QLoRA (Unsloth + trl)"
    status: str = "QUEUED"    # QUEUED | RUNNING | COMPLETE
    triggered_at: datetime = Field(default_factory=utcnow)


class DPOPair(BaseModel):
    prompt: str
    chosen: str
    rejected: str
    incident_id: Optional[str] = None


class ReviewRequest(BaseModel):
    action: ActionStatus
    reviewer_id: str
    feedback_notes: Optional[str] = None

    @model_validator(mode="after")
    def _valid_decision(self) -> "ReviewRequest":
        if self.action not in (ActionStatus.APPROVED, ActionStatus.REJECTED):
            raise ValueError("Action must be APPROVED or REJECTED")
        return self
