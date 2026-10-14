"""FastAPI application entrypoint — Core Orchestration & Event Bus."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import approvals, incidents, intelligence, network
from app.schemas.security import utcnow
from app.services.event_bus import bus, repo
from app.services.seed_data import seed_baselines, seed_demo_incidents, seed_topology
from app.services.training_pipeline import scrape_all_feeds


async def _baseline_updater() -> None:
    """Simulated live NetFlow/sFlow/eBPF telemetry stream for the visibility matrix."""
    import math
    import random
    from datetime import timedelta
    from app.schemas.security import BaselineBucket, utcnow
    while True:
        await asyncio.sleep(5)
        now = utcnow()
        last = repo.baselines[-1] if repo.baselines else None
        expected = 2_000_000_000 + int(400_000_000 * math.sin(now.timestamp() / 600))
        actual = expected + random.randint(-150_000_000, 220_000_000)
        score = round(min(1.0, abs(actual - expected) / 2_000_000_000), 3)
        repo.baselines.append(BaselineBucket(ts=now, expected_bps=expected, actual_bps=actual, anomaly_score=score))
        repo.baselines = repo.baselines[-120:]
        await bus.publish("visibility", {"type": "BASELINE_TICK", "ts": now.isoformat(),
                                         "expected_bps": expected, "actual_bps": actual,
                                         "anomaly_score": score})


async def _rule_expiry_sweeper() -> None:
    """Auto-expire temporary mitigations whose TTL elapsed.

    Guarantees Tier-1 autonomous drops and 1h scrub/rate-limit rules never
    silently persist past their approved window (least-privilege hygiene).
    """
    from app.services.mitigation_executor import rollback_mitigation
    while True:
        await asyncio.sleep(15)
        now = utcnow()
        for change in list(repo.policy_changes.values()):
            if (not change.rolled_back and change.expires_at is not None
                    and change.expires_at <= now):
                try:
                    await rollback_mitigation(change.id, actor="Rule_Expiry_Sweeper")
                except (KeyError, RuntimeError):
                    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Boot: seed topology/baselines/incidents and run first intel scrape.
    seed_topology()
    seed_baselines()
    await seed_demo_incidents()
    try:
        await asyncio.wait_for(scrape_all_feeds(), timeout=10)
    except (asyncio.TimeoutError, Exception):
        pass  # offline demo mode keeps curated corpus
    task = asyncio.create_task(_baseline_updater())
    sweeper = asyncio.create_task(_rule_expiry_sweeper())
    yield
    task.cancel()
    sweeper.cancel()


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(incidents.router)
app.include_router(approvals.router)
app.include_router(network.router)
app.include_router(intelligence.router)


@app.get("/api/v1/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "OPERATIONAL",
        "service": settings.app_name,
        "tenet": "Comprehensive Network Visibility is non-negotiable",
        "incidents": len(repo.incidents),
        "pending_approvals": len(repo.pending_approvals()),
        "active_mitigations": len(repo.active_mitigations()),
        "intel_corpus": len(repo.threat_intel),
        "verified_reviews": repo.verified_review_count,
        "dpo_trigger_threshold": settings.dpo_trigger_threshold,
    }


@app.websocket("/ws/telemetry")
async def telemetry_socket(websocket: WebSocket) -> None:
    """Real-time telemetry stream (WebSockets stand-in for gRPC/Redis pub-sub)."""
    await websocket.accept()
    queue = bus.subscribe("*")
    try:
        # Initial snapshot so dashboards render instantly.
        await websocket.send_json({"topic": "snapshot", "payload": {
            "incidents": [d.model_dump(mode="json") for d in list(repo.incidents.values())[:20]],
            "approvals": [p.model_dump(mode="json") for p in repo.pending_approvals()],
            "recent_events": list(bus.history)[:30],
        }})
        while True:
            record = await queue.get()
            await websocket.send_json(record)
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe("*", queue)
