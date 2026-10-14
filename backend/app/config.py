"""Application-wide settings for the Enterprise AI Security, AppSec & DDoS Platform."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CISOPULSE_", env_file=".env", extra="ignore")

    app_name: str = "AI Cybersecurity Command Center - IDS/IPS/Firewall/DDoS Core API"
    environment: str = "development"

    # --- Infrastructure connection strings (TimescaleDB / Neo4j / ClickHouse / Redis) ---
    timescale_dsn: str = "postgresql://ciso:ciso@localhost:5432/cisopulse"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "ciso"
    clickhouse_dsn: str = "clickhouse://localhost:9000/cisopulse"
    redis_url: str = "redis://localhost:6379/0"

    # When True the platform persists to TimescaleDB/Neo4j; otherwise an in-memory
    # repository keeps the whole stack runnable for demos and CI.
    persistence_enabled: bool = False

    # --- Automated DDoS Detection thresholds (Comprehensive Network Visibility tenet) ---
    ddos_bps_threshold: int = 1_000_000_000          # 1 Gbps volumetric anomaly
    ddos_pps_threshold: int = 500_000                # 500 kpps packet-rate anomaly
    l7_ddos_rps_threshold: int = 5_000               # application-layer requests/sec
    ids_high_severity: int = 3                       # severity >= 3 requires review

    # --- Continuous learning pipeline ---
    dpo_trigger_threshold: int = 1_000               # verified reviews before LoRA/QLoRA run
    scraper_interval_seconds: int = 3600

    # --- HITL gate ---
    tier1_autonomous_execution: bool = True


settings = Settings()
