"""Threat-intel feeds, training pipeline & audit endpoints."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from app.config import settings
from app.schemas.security import DPOPair, ThreatFeedItem
from app.services.event_bus import bus, repo
from app.services.training_pipeline import (
    FEEDS, curate_sft_samples, generate_dpo_pairs, maybe_trigger_fine_tuning, scrape_all_feeds,
)

router = APIRouter(prefix="/api/v1/intel", tags=["intelligence-training"])


@router.get("/feeds")
async def list_feeds() -> Dict[str, str]:
    return FEEDS


@router.post("/scrape/run")
async def run_scrape() -> Dict[str, Any]:
    added = await scrape_all_feeds()
    return {"new_entries": added, "corpus_size": len(repo.threat_intel),
            "embedded_in_pgvector": sum(1 for t in repo.threat_intel if t.embedded)}


@router.get("/entries", response_model=List[ThreatFeedItem])
async def intel_entries(feed: str | None = None, entry_type: str | None = None,
                        limit: int = 100) -> List[ThreatFeedItem]:
    out = repo.threat_intel
    if feed:
        out = [t for t in out if t.feed.lower() == feed.lower()]
    if entry_type:
        out = [t for t in out if t.entry_type.lower() == entry_type.lower()]
    return out[:limit]


@router.get("/training/status")
async def training_status() -> Dict[str, Any]:
    count = repo.verified_review_count
    return {
        "verified_review_count": count,
        "trigger_threshold": settings.dpo_trigger_threshold,
        "next_lora_run_in_reviews": max(0, settings.dpo_trigger_threshold - count),
        "jobs": [j.model_dump(mode="json") for j in repo.training_jobs],
        "method": "LoRA/QLoRA fine-tuning via Unsloth + HuggingFace trl",
    }


@router.get("/datasets/sft-preview")
async def sft_preview(limit: int = 20) -> List[Dict[str, Any]]:
    return curate_sft_samples()[:limit]


@router.get("/datasets/dpo-preview", response_model=List[DPOPair])
async def dpo_preview(limit: int = 20) -> List[DPOPair]:
    return generate_dpo_pairs()[:limit]


@router.post("/training/force-trigger")
async def force_trigger() -> Dict[str, Any]:
    """Ops override to queue a fine-tuning run regardless of review threshold."""
    job = await maybe_trigger_fine_tuning()
    if job is None:
        from app.schemas.security import TrainingJob
        sft, dpo = curate_sft_samples(), generate_dpo_pairs()
        import uuid
        job = TrainingJob(job_id=f"train-manual-{uuid.uuid4().hex[:8]}", dataset_kind="SFT+DPO",
                          sample_count=len(sft) + len(dpo), verified_review_count=repo.verified_review_count)
        repo.add_training_job(job)
        await bus.publish("training", {"type": "TRAINING_QUEUED", "job_id": job.job_id, "manual": True})
    return {"job_id": job.job_id, "status": job.status, "samples": job.sample_count}


@router.get("/audit")
async def audit_log(limit: int = 100) -> List[Dict[str, Any]]:
    return list(repo.audit_log)[:limit]
