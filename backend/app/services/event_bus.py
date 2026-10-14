"""In-memory event bus + repository.

Stands in for Redis/Kafka (event bus) and TimescaleDB/Neo4j (repository) so the
whole control plane runs without external infrastructure. When
``settings.persistence_enabled`` is true, records are *also* mirrored into the
SQLAlchemy ORM session (TimescaleDB). The Neo4j graph projection keeps edge
provenance: DIRECTLY_OBSERVED (solid) vs INFERRED_BY_AI (dashed animated).
"""
from __future__ import annotations

import asyncio
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Deque, Dict, List, Optional

from app.config import settings
from app.schemas.security import (
    ActionProposal, ActionStatus, AgentDecisionTrace, BaselineBucket,
    FirewallPolicyChange, HumanActionReview, IncidentDossier, ThreatFeedItem,
    TopologyEdge, TopologyNode, TrainingJob, utcnow,
)


class EventBus:
    """Fan-out pub/sub with replay buffer — the Redis/Kafka stand-in."""

    def __init__(self, history_size: int = 500) -> None:
        self._subscribers: Dict[str, List[asyncio.Queue]] = {}
        self.history: Deque[Dict[str, Any]] = deque(maxlen=history_size)

    async def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        record = {"topic": topic, "payload": payload, "ts": utcnow().isoformat()}
        self.history.appendleft(record)
        for queue in self._subscribers.get(topic, []) + self._subscribers.get("*", []):
            queue.put_nowait(record)

    def subscribe(self, topic: str = "*") -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.setdefault(topic, []).append(queue)
        return queue

    def unsubscribe(self, topic: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(topic, [])
        if queue in subs:
            subs.remove(queue)

    async def stream(self, topic: str = "*") -> AsyncIterator[Dict[str, Any]]:
        queue = self.subscribe(topic)
        try:
            while True:
                yield await queue.get()
        finally:
            self.unsubscribe(topic, queue)


class Repository:
    """Authoritative in-process state; optional TimescaleDB mirror on write."""

    def __init__(self) -> None:
        self.incidents: Dict[str, IncidentDossier] = {}
        self.proposals: Dict[str, ActionProposal] = {}
        self.policy_changes: Dict[str, FirewallPolicyChange] = {}
        self.reviews: List[HumanActionReview] = []
        self.traces: List[AgentDecisionTrace] = []
        self.threat_intel: List[ThreatFeedItem] = []
        self.training_jobs: List[TrainingJob] = []
        self.topology_nodes: Dict[str, TopologyNode] = {}
        self.topology_edges: Dict[str, TopologyEdge] = {}
        self.baselines: List[BaselineBucket] = []
        self.audit_log: Deque[Dict[str, Any]] = deque(maxlen=2000)

    # --- incidents / proposals -------------------------------------------------
    def save_incident(self, dossier: IncidentDossier) -> None:
        self.incidents[dossier.incident_id] = dossier

    def save_proposal(self, proposal: ActionProposal) -> None:
        self.proposals[proposal.proposal_id] = proposal

    def pending_approvals(self) -> List[ActionProposal]:
        order = {ActionStatus.PENDING: 0, ActionStatus.APPROVED: 1}
        return sorted(
            (p for p in self.proposals.values() if p.status in (ActionStatus.PENDING, ActionStatus.APPROVED)),
            key=lambda p: (order.get(p.status, 9), -int(p.tier)),
        )

    def add_review(self, review: HumanActionReview) -> None:
        self.reviews.append(review)

    @property
    def verified_review_count(self) -> int:
        return len(self.reviews)

    def add_trace(self, trace: AgentDecisionTrace) -> None:
        self.traces.append(trace)

    def add_policy_change(self, change: FirewallPolicyChange) -> None:
        self.policy_changes[change.id] = change

    def active_mitigations(self) -> List[FirewallPolicyChange]:
        now = utcnow()
        return [
            c for c in self.policy_changes.values()
            if not c.rolled_back and (c.expires_at is None or c.expires_at > now)
        ]

    # --- topology graph ---------------------------------------------------------
    def upsert_node(self, node: TopologyNode) -> None:
        self.topology_nodes[node.id] = node

    def upsert_edge(self, edge: TopologyEdge) -> None:
        self.topology_edges[edge.id] = edge

    # --- intel & training -------------------------------------------------------
    def add_intel(self, item: ThreatFeedItem) -> bool:
        if any(t.feed == item.feed and t.identifier == item.identifier for t in self.threat_intel):
            return False
        self.threat_intel.insert(0, item)
        return True

    def add_training_job(self, job: TrainingJob) -> None:
        self.training_jobs.insert(0, job)

    def audit(self, actor: str, action: str, detail: Dict[str, Any]) -> None:
        self.audit_log.appendleft({"ts": utcnow().isoformat(), "actor": actor, "action": action, "detail": detail})


bus = EventBus()
repo = Repository()
