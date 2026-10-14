"""SQLAlchemy ORM models mirroring the multi-modal database schema.

TimescaleDB (PostgreSQL) hosts these as hypertables for time-series telemetry;
Neo4j stores the entity-relationship graph (see sql/neo4j_schema.cypher) and
ClickHouse/pgvector hold high-throughput packet payload embeddings.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, BigInteger,
    String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    sector: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tier_level: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="Ingested")
    ciso_confidence_score: Mapped[float] = mapped_column(Float, default=0.0)
    attack_class: Mapped[str] = mapped_column(String(32), default="NONE")
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    telemetry: Mapped[list["NetworkAttackTelemetryLog"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    policy_changes: Mapped[list["FirewallPolicyChange"]] = relationship(back_populates="incident")
    traces: Mapped[list["AgentDecisionTrace"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )
    reviews: Mapped[list["HumanActionReview"]] = relationship(back_populates="incident")


class NetworkAttackTelemetryLog(Base):
    """Raw Telemetry, IDS/IPS, Firewall & DDoS Logs (hypertable partitioned by observed_at)."""
    __tablename__ = "network_attack_telemetry_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    log_type: Mapped[str] = mapped_column(String(64), nullable=False)
    src_ip: Mapped[str] = mapped_column(String(45), nullable=False)   # INET in Postgres
    dst_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    signature_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    traffic_volume_bps: Mapped[int | None] = mapped_column(BigInteger, nullable=True)   # DDoS visibility
    packets_per_second: Mapped[int | None] = mapped_column(BigInteger, nullable=True)   # DDoS visibility
    raw_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    parsed_entities: Mapped[dict] = mapped_column(JSON, default=dict)                    # JSONB
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    is_adversarial_pattern: Mapped[bool] = mapped_column(Boolean, default=False)

    incident: Mapped["Incident"] = relationship(back_populates="telemetry")


class FirewallPolicyChange(Base):
    __tablename__ = "firewall_policy_changes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False)      # DROP/REJECT/ALLOW/RATE_LIMIT/SCRUB_REDIRECT
    rule_definition: Mapped[dict] = mapped_column(JSON, default=dict)       # JSONB
    enforcement_layer: Mapped[str] = mapped_column(String(64), nullable=False)  # eBPF/IPTABLES/NGFW_API/CLOUDFLARE_WAF/BGP_FLOWSPEC
    applied_by_agent: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by_human: Mapped[str | None] = mapped_column(String(128), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    rolled_back: Mapped[bool] = mapped_column(Boolean, default=False)

    incident: Mapped["Incident"] = relationship(back_populates="policy_changes")


class AgentDecisionTrace(Base):
    __tablename__ = "agent_decision_traces"
    __table_args__ = (UniqueConstraint("incident_id", "agent_name", "step_number", name="uq_trace_step"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt_context: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_thought_process: Mapped[str] = mapped_column(Text, nullable=False)
    tool_calls_executed: Mapped[list] = mapped_column(JSON, default=list)
    hypotheses_evaluated: Mapped[list] = mapped_column(JSON, default=list)
    confidence_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="traces")


class HumanActionReview(Base):
    """HITL feedback history — consumed by the SFT/DPO dataset curators."""
    __tablename__ = "human_action_reviews"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    incident_id: Mapped[str | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    proposal_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    proposed_action: Mapped[dict] = mapped_column(JSON, default=dict)
    business_impact_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    action_taken: Mapped[str] = mapped_column(String(32), nullable=False)  # Approved/Modified/Rejected
    reviewer_id: Mapped[str] = mapped_column(String(128), nullable=False)
    human_feedback_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    incident: Mapped["Incident"] = relationship(back_populates="reviews")


class ThreatFeedEntry(Base):
    """Scraped intel (ET rules, Snort, YARA, CISA KEV, AbuseIPDB, CF Radar...) + pgvector embedding ref."""
    __tablename__ = "threat_feed_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    feed: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entry_type: Mapped[str] = mapped_column(String(32), nullable=False)
    identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    content: Mapped[str] = mapped_column(Text, default="")
    embedding_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)  # pgvector row key
    scraped_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class TrainingJobRecord(Base):
    __tablename__ = "training_jobs"

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    dataset_kind: Mapped[str] = mapped_column(String(16), nullable=False)  # SFT | DPO
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    verified_review_count: Mapped[int] = mapped_column(Integer, default=0)
    base_model: Mapped[str] = mapped_column(String(128), default="llama-3.1-8b-instruct")
    method: Mapped[str] = mapped_column(String(64), default="LoRA/QLoRA (Unsloth + trl)")
    status: Mapped[str] = mapped_column(String(16), default="QUEUED")
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
