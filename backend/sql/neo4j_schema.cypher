// =============================================================================
// Neo4j Entity-Relationship Graph Schema (Live Incident & Network Topology)
// Run with: cypher-shell -u neo4j -p ciso -f neo4j_schema.cypher
// =============================================================================

CREATE CONSTRAINT incident_uid IF NOT EXISTS FOR (i:Incident) REQUIRE i.incident_id IS UNIQUE;
CREATE CONSTRAINT ip_uid IF NOT EXISTS FOR (n:IPAddress) REQUIRE n.ip IS UNIQUE;
CREATE CONSTRAINT host_uid IF NOT EXISTS FOR (h:Host) REQUIRE h.host_id IS UNIQUE;
CREATE CONSTRAINT fw_uid IF NOT EXISTS FOR (f:Firewall) REQUIRE f.device_id IS UNIQUE;
CREATE CONSTRAINT sensor_uid IF NOT EXISTS FOR (s:IDSSensor) REQUIRE s.sensor_id IS UNIQUE;

CREATE INDEX tier_idx IF NOT EXISTS FOR (i:Incident) ON (i.tier_level);
CREATE INDEX status_idx IF NOT EXISTS FOR (i:Incident) ON (i.status);
CREATE INDEX adversarial_idx IF NOT EXISTS FOR (n:IPAddress) ON (n.is_adversarial);

// --- Canonical topology node labels -----------------------------------------
// (:Identity {name, role, risk_score})
// (:Host {host_id, ip, os, zone})
// (:Firewall {device_id, vendor: 'PaloAlto|Fortinet', model, mgmt_api})
// (:IDSSensor {sensor_id, engine: 'Suricata|Zeek|eBPF', location})
// (:ScrubbingCenter {name, provider: 'CloudflareRadar|Akamai', capacity_gbps})
// (:MCPServer {name, endpoint, auth_mode})
// (:Alert {alert_id, signature_id, severity, observed_at})
// (:ThreatActor {alias, attribution_confidence})

// --- Relationship types -------------------------------------------------------
// (:IPAddress)-[:DIRECTLY_OBSERVED {bps, pps, sid, pcap_ref}]->(:Host)
//     Solid glowing edges in the UI: raw packet-log provenance.
// (:Alert)-[:INFERRED_BY_AI {model, confidence, reasoning}]->(:Host)
//     Dashed animated edges: AI-attack-path inference only.
// (:Incident)-[:HAS_ALERT]->(:Alert)
// (:Incident)-[:MITIGATED_BY]->(:FirewallPolicyChange)
// (:Firewall)-[:FORWARDS_TO]->(:ScrubbingCenter)
// (:ThreatActor)-[:LAUNCHED]->(:Incident)
// (:Identity)-[:USES]->(:Host)
// (:MCPServer)-[:EXPOSES_TOOL]->(:ActionProposal)

// Example ingestion query (parameterized from FastAPI event bus):
// MERGE (src:IPAddress {ip: $src_ip}) ON CREATE SET src.is_adversarial = true
// MERGE (dst:Host {host_id: $dst_host})
// MERGE (src)-[r:DIRECTLY_OBSERVED]->(dst)
// SET r.bps = $bps, r.pps = $pps, r.sid = $signature_id, r.updated_at = datetime();
