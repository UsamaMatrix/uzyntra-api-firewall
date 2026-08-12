use std::{fs, path::Path};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{
    params, params_from_iter,
    types::Value as SqlValue,
    Connection,
};

use crate::{
    mitigation::ActiveMitigation,
    types::{AdminAudit, AnalystSuppression, ApprovedShadowRoute, AuditSearchFilters, EventSearchFilters, LearnedRoute, ManagedSpecReleaseState, ManagedSpecRoute, PersistedBehaviorSnapshot, PolicyBundle, PolicyTimelineEntry, PrincipalAllowlistEntry, PromotedSpecRoute, ResponseContract, RestoreRefusalAlert, RestoreRefusalEvent, ScopedPrincipalAllowlistEntry, ScopedSourceAllowlistEntry, SecurityEvent, Severity, SourceAllowlistEntry, SourceReputation, TriScopedAllowlistEntry},
};

pub fn init_db(sqlite_path: &str) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    conn.execute_batch(
        r#"
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA journal_mode = DELETE;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL
        );

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (1, 'initial_sqlite_persistence', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (2, 'phase_7_pagination_and_admin_actions', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (3, 'phase_3_learned_routes', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (4, 'phase_7_behavior_and_shadow_approval', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (5, 'phase_8_promoted_spec_routes', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (6, 'phase_9_managed_spec_and_suppressions', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (7, 'phase_10_allowlists', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (8, 'phase_11_response_contracts_and_policy_bundles', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (9, 'phase_12_scoped_allowlists_and_signed_bundles', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (10, 'phase_13_tri_scoped_allowlist', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (11, 'phase_15_restore_refusals_and_release_channels', CURRENT_TIMESTAMP);

        INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
        VALUES (12, 'phase_16_restore_refusal_alerts', CURRENT_TIMESTAMP);

        CREATE TABLE IF NOT EXISTS restore_refusal_alerts (
            alert_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT NOT NULL,
            stored_digest_sha256 TEXT NOT NULL,
            recomputed_digest_sha256 TEXT NOT NULL,
            latest_actor TEXT NOT NULL,
            alert_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_restore_refusal_alerts_status
            ON restore_refusal_alerts(status);

        CREATE INDEX IF NOT EXISTS idx_restore_refusal_alerts_created_at
            ON restore_refusal_alerts(created_at DESC);

        CREATE TABLE IF NOT EXISTS restore_refusals (
            refusal_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            stored_digest_sha256 TEXT NOT NULL,
            recomputed_digest_sha256 TEXT NOT NULL,
            refusal_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_restore_refusals_timestamp
            ON restore_refusals(timestamp DESC);

        CREATE TABLE IF NOT EXISTS managed_spec_release_state (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            channel TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            note TEXT,
            state_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_managed_spec_release_state_channel
            ON managed_spec_release_state(channel);

        CREATE TABLE IF NOT EXISTS tri_scoped_allowlist (
            allowlist_key TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            principal_prefix TEXT NOT NULL,
            path_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scoped_source_allowlist (
            allowlist_key TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            path_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scoped_principal_allowlist (
            allowlist_key TEXT PRIMARY KEY,
            principal_prefix TEXT NOT NULL,
            path_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS response_contracts (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            expected_status INTEGER NOT NULL,
            expected_content_type_prefix TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            note TEXT,
            contract_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS policy_bundles (
            bundle_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            note TEXT,
            bundle_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_policy_bundles_created_at
            ON policy_bundles(created_at DESC);

        CREATE TABLE IF NOT EXISTS source_allowlist (
            source_ip TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS principal_allowlist (
            principal_prefix TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            entry_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS managed_spec_routes (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            managed_at TEXT NOT NULL,
            managed_by TEXT NOT NULL,
            auth_required INTEGER NOT NULL,
            note TEXT,
            route_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_managed_spec_routes_managed_at
            ON managed_spec_routes(managed_at DESC);

        CREATE TABLE IF NOT EXISTS analyst_suppressions (
            suppression_key TEXT PRIMARY KEY,
            rule_id TEXT NOT NULL,
            path_prefix TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT,
            suppression_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_analyst_suppressions_rule_id
            ON analyst_suppressions(rule_id);

        CREATE TABLE IF NOT EXISTS promoted_spec_routes (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            promoted_at TEXT NOT NULL,
            promoted_by TEXT NOT NULL,
            source TEXT NOT NULL,
            note TEXT,
            route_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_promoted_spec_routes_promoted_at
            ON promoted_spec_routes(promoted_at DESC);

        CREATE TABLE IF NOT EXISTS behavior_snapshots (
            principal_route_key TEXT NOT NULL,
            captured_at TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            PRIMARY KEY(principal_route_key, captured_at)
        );

        CREATE INDEX IF NOT EXISTS idx_behavior_snapshots_captured_at
            ON behavior_snapshots(captured_at DESC);

        CREATE TABLE IF NOT EXISTS approved_shadow_routes (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            approved_at TEXT NOT NULL,
            approved_by TEXT NOT NULL,
            note TEXT,
            approval_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_approved_shadow_routes_approved_at
            ON approved_shadow_routes(approved_at DESC);

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            rule_ids TEXT NOT NULL,
            highest_severity TEXT NOT NULL,
            outcome TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip);
        CREATE INDEX IF NOT EXISTS idx_security_events_request_id
            ON security_events(request_id);
        CREATE INDEX IF NOT EXISTS idx_security_events_rule_ids
            ON security_events(rule_ids);
        CREATE INDEX IF NOT EXISTS idx_security_events_highest_severity
            ON security_events(highest_severity);
        CREATE INDEX IF NOT EXISTS idx_security_events_method
            ON security_events(method);
        CREATE INDEX IF NOT EXISTS idx_security_events_path
            ON security_events(path);

        CREATE TABLE IF NOT EXISTS admin_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            details TEXT NOT NULL,
            audit_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_admin_audits_timestamp
            ON admin_audits(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_actor
            ON admin_audits(actor);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_action
            ON admin_audits(action);
        CREATE INDEX IF NOT EXISTS idx_admin_audits_target
            ON admin_audits(target);

        CREATE TABLE IF NOT EXISTS active_mitigations (
            source_ip TEXT PRIMARY KEY,
            action_id TEXT NOT NULL,
            action_type TEXT NOT NULL,
            ttl_secs INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            reason TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_active_mitigations_expires_at
            ON active_mitigations(expires_at);

        CREATE TABLE IF NOT EXISTS reputations (
            source_ip TEXT PRIMARY KEY,
            suspicious_score INTEGER NOT NULL,
            last_seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS learned_routes (
            route_key TEXT PRIMARY KEY,
            method TEXT NOT NULL,
            normalized_path TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            hits INTEGER NOT NULL,
            has_auth INTEGER NOT NULL,
            route_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_learned_routes_last_seen
            ON learned_routes(last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_learned_routes_method
            ON learned_routes(method);
        CREATE INDEX IF NOT EXISTS idx_learned_routes_path
            ON learned_routes(normalized_path);
        "#,
    )?;

    Ok(())
}

pub fn persist_security_event(sqlite_path: &str, event: &SecurityEvent) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let json = serde_json::to_string(event)?;
    let rule_ids = event
        .findings
        .iter()
        .map(|f| f.rule_id.clone())
        .collect::<Vec<_>>()
        .join(",");

    let highest_severity = event
        .findings
        .iter()
        .map(|f| severity_rank(&f.severity))
        .max()
        .map(rank_to_severity_name)
        .unwrap_or("low")
        .to_string();

    let outcome = match &event.decision.outcome {
        crate::types::DecisionOutcome::Allow => "allow".to_string(),
        crate::types::DecisionOutcome::Reject { status_code, .. } => {
            format!("reject:{status_code}")
        }
    };

    conn.execute(
        r#"
        INSERT INTO security_events
        (request_id, timestamp, source_ip, method, path, rule_ids, highest_severity, outcome, event_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            event.request_id,
            event.timestamp.to_rfc3339(),
            event.source_ip,
            event.method,
            event.path,
            rule_ids,
            highest_severity,
            outcome,
            json
        ],
    )?;

    Ok(())
}

pub fn persist_admin_audit(sqlite_path: &str, audit: &AdminAudit) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let json = serde_json::to_string(audit)?;

    conn.execute(
        r#"
        INSERT INTO admin_audits
        (timestamp, actor, action, target, result, details, audit_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            audit.timestamp.to_rfc3339(),
            audit.actor,
            audit.action,
            audit.target,
            audit.result,
            audit.details,
            json
        ],
    )?;

    Ok(())
}

pub fn query_security_events(
    sqlite_path: &str,
    filters: &EventSearchFilters,
) -> Result<Vec<SecurityEvent>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let mut sql = String::from("SELECT event_json FROM security_events WHERE 1=1");
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(source_ip) = &filters.source_ip {
        sql.push_str(" AND source_ip = ?");
        values.push(SqlValue::Text(source_ip.clone()));
    }

    if let Some(rule_id) = &filters.rule_id {
        sql.push_str(" AND rule_ids LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", rule_id)));
    }

    if let Some(severity) = &filters.severity {
        sql.push_str(" AND highest_severity = ?");
        values.push(SqlValue::Text(severity.to_ascii_lowercase()));
    }

    if let Some(method) = &filters.method {
        sql.push_str(" AND method = ?");
        values.push(SqlValue::Text(method.to_ascii_uppercase()));
    }

    if let Some(path_contains) = &filters.path_contains {
        sql.push_str(" AND path LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", path_contains)));
    }

    if let Some(since) = &filters.since {
        sql.push_str(" AND timestamp >= ?");
        values.push(SqlValue::Text(normalize_rfc3339(since)?));
    }

    if let Some(until) = &filters.until {
        sql.push_str(" AND timestamp <= ?");
        values.push(SqlValue::Text(normalize_rfc3339(until)?));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    values.push(SqlValue::Integer(filters.limit.unwrap_or(20).clamp(1, 500) as i64));
    values.push(SqlValue::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let event: SecurityEvent = serde_json::from_str(&json)?;
        items.push(event);
    }

    Ok(items)
}

pub fn query_admin_audits(
    sqlite_path: &str,
    filters: &AuditSearchFilters,
) -> Result<Vec<AdminAudit>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)
        .with_context(|| format!("failed to open SQLite database at {}", sqlite_path))?;

    let mut sql = String::from("SELECT audit_json FROM admin_audits WHERE 1=1");
    let mut values: Vec<SqlValue> = Vec::new();

    if let Some(actor) = &filters.actor {
        sql.push_str(" AND actor = ?");
        values.push(SqlValue::Text(actor.clone()));
    }

    if let Some(action) = &filters.action {
        sql.push_str(" AND action = ?");
        values.push(SqlValue::Text(action.clone()));
    }

    if let Some(target) = &filters.target {
        sql.push_str(" AND target LIKE ?");
        values.push(SqlValue::Text(format!("%{}%", target)));
    }

    if let Some(since) = &filters.since {
        sql.push_str(" AND timestamp >= ?");
        values.push(SqlValue::Text(normalize_rfc3339(since)?));
    }

    if let Some(until) = &filters.until {
        sql.push_str(" AND timestamp <= ?");
        values.push(SqlValue::Text(normalize_rfc3339(until)?));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    values.push(SqlValue::Integer(filters.limit.unwrap_or(20).clamp(1, 500) as i64));
    values.push(SqlValue::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(values.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let audit: AdminAudit = serde_json::from_str(&json)?;
        items.push(audit);
    }

    Ok(items)
}

pub fn upsert_active_mitigation(sqlite_path: &str, mitigation: &ActiveMitigation) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)?;
    let (action_type, ttl_secs) = match mitigation.action {
        crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs } => {
            ("block_source_ip_temporary".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::ThrottleSource { ttl_secs } => {
            ("throttle_source".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::MarkSourceSuspicious { ttl_secs } => {
            ("mark_source_suspicious".to_string(), ttl_secs as i64)
        }
        crate::types::MitigationAction::BlockRequest => ("block_request".to_string(), 0),
    };

    conn.execute(
        r#"
        INSERT INTO active_mitigations
        (source_ip, action_id, action_type, ttl_secs, created_at, expires_at, reason)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(source_ip) DO UPDATE SET
            action_id = excluded.action_id,
            action_type = excluded.action_type,
            ttl_secs = excluded.ttl_secs,
            created_at = excluded.created_at,
            expires_at = excluded.expires_at,
            reason = excluded.reason
        "#,
        params![
            mitigation.source_ip.to_string(),
            mitigation.action_id,
            action_type,
            ttl_secs,
            mitigation.created_at.to_rfc3339(),
            mitigation.expires_at.to_rfc3339(),
            mitigation.reason
        ],
    )?;

    Ok(())
}

pub fn delete_active_mitigation(sqlite_path: &str, source_ip: &str) -> Result<()> {
    let conn = Connection::open(sqlite_path)?;
    conn.execute(
        "DELETE FROM active_mitigations WHERE source_ip = ?1",
        params![source_ip],
    )?;
    Ok(())
}

pub fn load_active_mitigations(sqlite_path: &str) -> Result<Vec<ActiveMitigation>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT source_ip, action_id, action_type, ttl_secs, created_at, expires_at, reason
        FROM active_mitigations
        ORDER BY expires_at ASC
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        let source_ip: String = row.get(0)?;
        let action_id: String = row.get(1)?;
        let action_type: String = row.get(2)?;
        let ttl_secs: i64 = row.get(3)?;
        let created_at: String = row.get(4)?;
        let expires_at: String = row.get(5)?;
        let reason: String = row.get(6)?;

        let action = match action_type.as_str() {
            "block_source_ip_temporary" => {
                crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs: ttl_secs as u64 }
            }
            "throttle_source" => crate::types::MitigationAction::ThrottleSource { ttl_secs: ttl_secs as u64 },
            "mark_source_suspicious" => {
                crate::types::MitigationAction::MarkSourceSuspicious { ttl_secs: ttl_secs as u64 }
            }
            _ => crate::types::MitigationAction::BlockSourceIpTemporary { ttl_secs: ttl_secs as u64 },
        };

        Ok(ActiveMitigation {
            action_id,
            source_ip: source_ip.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
            action,
            created_at: parse_rfc3339_to_utc(&created_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
            expires_at: parse_rfc3339_to_utc(&expires_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
            reason,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    Ok(items)
}

pub fn upsert_reputation(sqlite_path: &str, reputation: &SourceReputation) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)?;
    conn.execute(
        r#"
        INSERT INTO reputations (source_ip, suspicious_score, last_seen_at)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(source_ip) DO UPDATE SET
            suspicious_score = excluded.suspicious_score,
            last_seen_at = excluded.last_seen_at
        "#,
        params![
            reputation.source_ip,
            reputation.suspicious_score,
            reputation.last_seen_at.to_rfc3339()
        ],
    )?;
    Ok(())
}

pub fn load_reputations(sqlite_path: &str) -> Result<Vec<SourceReputation>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT source_ip, suspicious_score, last_seen_at
        FROM reputations
        ORDER BY last_seen_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| {
        let source_ip: String = row.get(0)?;
        let suspicious_score: i32 = row.get(1)?;
        let last_seen_at: String = row.get(2)?;

        Ok(SourceReputation {
            source_ip,
            suspicious_score,
            last_seen_at: parse_rfc3339_to_utc(&last_seen_at).map_err(|_| rusqlite::Error::InvalidQuery)?,
        })
    })?;

    let mut items = Vec::new();
    for row in rows {
        items.push(row?);
    }

    Ok(items)
}

pub fn delete_reputation(sqlite_path: &str, source_ip: &str) -> Result<()> {
    let conn = Connection::open(sqlite_path)?;
    conn.execute("DELETE FROM reputations WHERE source_ip = ?1", params![source_ip])?;
    Ok(())
}

pub fn upsert_learned_route(sqlite_path: &str, route: &LearnedRoute) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
    let json = serde_json::to_string(route)?;

    conn.execute(
        r#"
        INSERT INTO learned_routes
        (route_key, method, normalized_path, first_seen, last_seen, hits, has_auth, route_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(route_key) DO UPDATE SET
            first_seen = CASE
                WHEN excluded.first_seen < learned_routes.first_seen THEN excluded.first_seen
                ELSE learned_routes.first_seen
            END,
            last_seen = CASE
                WHEN excluded.last_seen > learned_routes.last_seen THEN excluded.last_seen
                ELSE learned_routes.last_seen
            END,
            hits = CASE
                WHEN excluded.hits > learned_routes.hits THEN excluded.hits
                ELSE learned_routes.hits
            END,
            has_auth = CASE
                WHEN excluded.has_auth > learned_routes.has_auth THEN excluded.has_auth
                ELSE learned_routes.has_auth
            END,
            route_json = excluded.route_json
        "#,
        params![
            route_key,
            route.method,
            route.normalized_path,
            route.first_seen.to_rfc3339(),
            route.last_seen.to_rfc3339(),
            route.hits as i64,
            if route.has_auth { 1i64 } else { 0i64 },
            json
        ],
    )?;

    Ok(())
}

pub fn replace_learned_routes(sqlite_path: &str, routes: &[LearnedRoute]) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;

    let mut conn = Connection::open(sqlite_path)?;
    let tx = conn.transaction()?;

    tx.execute("DELETE FROM learned_routes", [])?;

    for route in routes {
        let route_key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
        let json = serde_json::to_string(route)?;

        tx.execute(
            r#"
            INSERT INTO learned_routes
            (route_key, method, normalized_path, first_seen, last_seen, hits, has_auth, route_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                route_key,
                route.method,
                route.normalized_path,
                route.first_seen.to_rfc3339(),
                route.last_seen.to_rfc3339(),
                route.hits as i64,
                if route.has_auth { 1i64 } else { 0i64 },
                json
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

pub fn load_learned_routes(sqlite_path: &str) -> Result<Vec<LearnedRoute>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT route_json
        FROM learned_routes
        ORDER BY last_seen DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let route: LearnedRoute = serde_json::from_str(&json)?;
        items.push(route);
    }

    Ok(items)
}

pub fn query_learned_routes(sqlite_path: &str) -> Result<Vec<LearnedRoute>> {
    load_learned_routes(sqlite_path)
}

pub fn replace_behavior_snapshots(
    sqlite_path: &str,
    snapshots: &[PersistedBehaviorSnapshot],
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let mut conn = Connection::open(sqlite_path)?;
    let tx = conn.transaction()?;

    tx.execute("DELETE FROM behavior_snapshots", [])?;

    for snapshot in snapshots {
        let json = serde_json::to_string(snapshot)?;
        tx.execute(
            r#"
            INSERT INTO behavior_snapshots
            (principal_route_key, captured_at, snapshot_json)
            VALUES (?1, ?2, ?3)
            "#,
            params![
                snapshot.principal_route_key,
                snapshot.captured_at.to_rfc3339(),
                json
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

pub fn query_behavior_snapshots(sqlite_path: &str) -> Result<Vec<PersistedBehaviorSnapshot>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT snapshot_json
        FROM behavior_snapshots
        ORDER BY captured_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let snapshot: PersistedBehaviorSnapshot = serde_json::from_str(&json)?;
        items.push(snapshot);
    }

    Ok(items)
}

pub fn upsert_approved_shadow_route(
    sqlite_path: &str,
    route: &ApprovedShadowRoute,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
    let json = serde_json::to_string(route)?;

    conn.execute(
        r#"
        INSERT INTO approved_shadow_routes
        (route_key, method, normalized_path, approved_at, approved_by, note, approval_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(route_key) DO UPDATE SET
            approved_at = excluded.approved_at,
            approved_by = excluded.approved_by,
            note = excluded.note,
            approval_json = excluded.approval_json
        "#,
        params![
            route_key,
            route.method,
            route.normalized_path,
            route.approved_at.to_rfc3339(),
            route.approved_by,
            route.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_approved_shadow_routes(sqlite_path: &str) -> Result<Vec<ApprovedShadowRoute>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT approval_json
        FROM approved_shadow_routes
        ORDER BY approved_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: ApprovedShadowRoute = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_approved_shadow_route(
    sqlite_path: &str,
    method: &str,
    normalized_path: &str,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let affected = conn.execute(
        "DELETE FROM approved_shadow_routes WHERE route_key = ?1",
        params![route_key],
    )?;

    Ok(affected > 0)
}

pub fn upsert_promoted_spec_route(
    sqlite_path: &str,
    route: &PromotedSpecRoute,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
    let json = serde_json::to_string(route)?;

    conn.execute(
        r#"
        INSERT INTO promoted_spec_routes
        (route_key, method, normalized_path, promoted_at, promoted_by, source, note, route_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(route_key) DO UPDATE SET
            promoted_at = excluded.promoted_at,
            promoted_by = excluded.promoted_by,
            source = excluded.source,
            note = excluded.note,
            route_json = excluded.route_json
        "#,
        params![
            route_key,
            route.method,
            route.normalized_path,
            route.promoted_at.to_rfc3339(),
            route.promoted_by,
            route.source,
            route.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_promoted_spec_routes(sqlite_path: &str) -> Result<Vec<PromotedSpecRoute>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT route_json
        FROM promoted_spec_routes
        ORDER BY promoted_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: PromotedSpecRoute = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_promoted_spec_route(
    sqlite_path: &str,
    method: &str,
    normalized_path: &str,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let affected = conn.execute(
        "DELETE FROM promoted_spec_routes WHERE route_key = ?1",
        params![route_key],
    )?;

    Ok(affected > 0)
}

pub fn upsert_managed_spec_route(
    sqlite_path: &str,
    route: &ManagedSpecRoute,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
    let json = serde_json::to_string(route)?;

    conn.execute(
        r#"
        INSERT INTO managed_spec_routes
        (route_key, method, normalized_path, managed_at, managed_by, auth_required, note, route_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(route_key) DO UPDATE SET
            managed_at = excluded.managed_at,
            managed_by = excluded.managed_by,
            auth_required = excluded.auth_required,
            note = excluded.note,
            route_json = excluded.route_json
        "#,
        params![
            route_key,
            route.method,
            route.normalized_path,
            route.managed_at.to_rfc3339(),
            route.managed_by,
            if route.auth_required { 1i64 } else { 0i64 },
            route.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_managed_spec_routes(sqlite_path: &str) -> Result<Vec<ManagedSpecRoute>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT route_json
        FROM managed_spec_routes
        ORDER BY managed_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: ManagedSpecRoute = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_managed_spec_route(
    sqlite_path: &str,
    method: &str,
    normalized_path: &str,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let affected = conn.execute(
        "DELETE FROM managed_spec_routes WHERE route_key = ?1",
        params![route_key],
    )?;

    Ok(affected > 0)
}

pub fn upsert_analyst_suppression(
    sqlite_path: &str,
    item: &AnalystSuppression,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let suppression_key = match &item.path_prefix {
        Some(prefix) => format!("{}|{}", item.rule_id, prefix),
        None => format!("{}|*", item.rule_id),
    };
    let json = serde_json::to_string(item)?;

    conn.execute(
        r#"
        INSERT INTO analyst_suppressions
        (suppression_key, rule_id, path_prefix, created_at, created_by, reason, suppression_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(suppression_key) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            suppression_json = excluded.suppression_json
        "#,
        params![
            suppression_key,
            item.rule_id,
            item.path_prefix,
            item.created_at.to_rfc3339(),
            item.created_by,
            item.reason,
            json
        ],
    )?;

    Ok(())
}

pub fn query_analyst_suppressions(sqlite_path: &str) -> Result<Vec<AnalystSuppression>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT suppression_json
        FROM analyst_suppressions
        ORDER BY created_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: AnalystSuppression = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_analyst_suppression(
    sqlite_path: &str,
    rule_id: &str,
    path_prefix: Option<&str>,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let suppression_key = match path_prefix {
        Some(prefix) => format!("{}|{}", rule_id, prefix),
        None => format!("{}|*", rule_id),
    };

    let affected = conn.execute(
        "DELETE FROM analyst_suppressions WHERE suppression_key = ?1",
        params![suppression_key],
    )?;

    Ok(affected > 0)
}

pub fn upsert_source_allowlist(
    sqlite_path: &str,
    entry: &SourceAllowlistEntry,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let json = serde_json::to_string(entry)?;

    conn.execute(
        r#"
        INSERT INTO source_allowlist
        (source_ip, created_at, created_by, reason, entry_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(source_ip) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            entry_json = excluded.entry_json
        "#,
        params![
            entry.source_ip,
            entry.created_at.to_rfc3339(),
            entry.created_by,
            entry.reason,
            json
        ],
    )?;

    Ok(())
}

pub fn query_source_allowlist(sqlite_path: &str) -> Result<Vec<SourceAllowlistEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT entry_json
        FROM source_allowlist
        ORDER BY created_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: SourceAllowlistEntry = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_source_allowlist(sqlite_path: &str, source_ip: &str) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let affected = conn.execute(
        "DELETE FROM source_allowlist WHERE source_ip = ?1",
        params![source_ip],
    )?;

    Ok(affected > 0)
}

pub fn upsert_principal_allowlist(
    sqlite_path: &str,
    entry: &PrincipalAllowlistEntry,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let json = serde_json::to_string(entry)?;

    conn.execute(
        r#"
        INSERT INTO principal_allowlist
        (principal_prefix, created_at, created_by, reason, entry_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(principal_prefix) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            entry_json = excluded.entry_json
        "#,
        params![
            entry.principal_prefix,
            entry.created_at.to_rfc3339(),
            entry.created_by,
            entry.reason,
            json
        ],
    )?;

    Ok(())
}

pub fn query_principal_allowlist(sqlite_path: &str) -> Result<Vec<PrincipalAllowlistEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT entry_json
        FROM principal_allowlist
        ORDER BY created_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: PrincipalAllowlistEntry = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_principal_allowlist(sqlite_path: &str, principal_prefix: &str) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let affected = conn.execute(
        "DELETE FROM principal_allowlist WHERE principal_prefix = ?1",
        params![principal_prefix],
    )?;

    Ok(affected > 0)
}

pub fn upsert_response_contract(
    sqlite_path: &str,
    contract: &ResponseContract,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", contract.method.to_ascii_uppercase(), contract.normalized_path);
    let json = serde_json::to_string(contract)?;

    conn.execute(
        r#"
        INSERT INTO response_contracts
        (route_key, method, normalized_path, expected_status, expected_content_type_prefix, approved_at, approved_by, note, contract_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(route_key) DO UPDATE SET
            expected_status = excluded.expected_status,
            expected_content_type_prefix = excluded.expected_content_type_prefix,
            approved_at = excluded.approved_at,
            approved_by = excluded.approved_by,
            note = excluded.note,
            contract_json = excluded.contract_json
        "#,
        params![
            route_key,
            contract.method,
            contract.normalized_path,
            contract.expected_status as i64,
            contract.expected_content_type_prefix,
            contract.approved_at.to_rfc3339(),
            contract.approved_by,
            contract.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_response_contracts(sqlite_path: &str) -> Result<Vec<ResponseContract>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT contract_json
        FROM response_contracts
        ORDER BY approved_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let item: ResponseContract = serde_json::from_str(&json)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_response_contract(
    sqlite_path: &str,
    method: &str,
    normalized_path: &str,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let affected = conn.execute(
        "DELETE FROM response_contracts WHERE route_key = ?1",
        params![route_key],
    )?;

    Ok(affected > 0)
}

pub fn save_policy_bundle(sqlite_path: &str, bundle: &PolicyBundle) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let json = serde_json::to_string(bundle)?;

    conn.execute(
        r#"
        INSERT INTO policy_bundles
        (bundle_id, created_at, created_by, note, bundle_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            bundle.bundle_id,
            bundle.created_at.to_rfc3339(),
            bundle.created_by,
            bundle.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_policy_bundles(sqlite_path: &str) -> Result<Vec<PolicyBundle>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT bundle_json
        FROM policy_bundles
        ORDER BY created_at DESC
        "#,
    )?;

    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let mut item: PolicyBundle = serde_json::from_str(&json)?;
        if item.digest_sha256.is_empty() {
            item.digest_sha256 = crate::core::compute_live_policy_digest(&item.live_policy);
        }
        items.push(item);
    }

    Ok(items)
}

pub fn get_policy_bundle(sqlite_path: &str, bundle_id: &str) -> Result<Option<PolicyBundle>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(None);
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        "SELECT bundle_json FROM policy_bundles WHERE bundle_id = ?1 LIMIT 1"
    )?;

    let mut rows = stmt.query(params![bundle_id])?;
    if let Some(row) = rows.next()? {
        let json: String = row.get(0)?;
        let mut item: PolicyBundle = serde_json::from_str(&json)?;
        if item.digest_sha256.is_empty() {
            item.digest_sha256 = crate::core::compute_live_policy_digest(&item.live_policy);
        }
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

pub fn upsert_scoped_source_allowlist(
    sqlite_path: &str,
    entry: &ScopedSourceAllowlistEntry,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}", entry.source_ip, entry.path_prefix);
    let json = serde_json::to_string(entry)?;

    conn.execute(
        r#"
        INSERT INTO scoped_source_allowlist
        (allowlist_key, source_ip, path_prefix, created_at, created_by, reason, entry_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(allowlist_key) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            entry_json = excluded.entry_json
        "#,
        params![key, entry.source_ip, entry.path_prefix, entry.created_at.to_rfc3339(), entry.created_by, entry.reason, json],
    )?;

    Ok(())
}

pub fn query_scoped_source_allowlist(sqlite_path: &str) -> Result<Vec<ScopedSourceAllowlistEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare("SELECT entry_json FROM scoped_source_allowlist ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: ScopedSourceAllowlistEntry = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_scoped_source_allowlist(sqlite_path: &str, source_ip: &str, path_prefix: &str) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}", source_ip, path_prefix);
    let affected = conn.execute("DELETE FROM scoped_source_allowlist WHERE allowlist_key = ?1", params![key])?;

    Ok(affected > 0)
}

pub fn upsert_scoped_principal_allowlist(
    sqlite_path: &str,
    entry: &ScopedPrincipalAllowlistEntry,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}", entry.principal_prefix, entry.path_prefix);
    let json = serde_json::to_string(entry)?;

    conn.execute(
        r#"
        INSERT INTO scoped_principal_allowlist
        (allowlist_key, principal_prefix, path_prefix, created_at, created_by, reason, entry_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(allowlist_key) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            entry_json = excluded.entry_json
        "#,
        params![key, entry.principal_prefix, entry.path_prefix, entry.created_at.to_rfc3339(), entry.created_by, entry.reason, json],
    )?;

    Ok(())
}

pub fn query_scoped_principal_allowlist(sqlite_path: &str) -> Result<Vec<ScopedPrincipalAllowlistEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare("SELECT entry_json FROM scoped_principal_allowlist ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: ScopedPrincipalAllowlistEntry = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_scoped_principal_allowlist(sqlite_path: &str, principal_prefix: &str, path_prefix: &str) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}", principal_prefix, path_prefix);
    let affected = conn.execute("DELETE FROM scoped_principal_allowlist WHERE allowlist_key = ?1", params![key])?;

    Ok(affected > 0)
}

pub fn upsert_tri_scoped_allowlist(sqlite_path: &str, entry: &TriScopedAllowlistEntry) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}|{}", entry.source_ip, entry.principal_prefix, entry.path_prefix);
    let json = serde_json::to_string(entry)?;

    conn.execute(
        r#"
        INSERT INTO tri_scoped_allowlist
        (allowlist_key, source_ip, principal_prefix, path_prefix, created_at, created_by, reason, entry_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(allowlist_key) DO UPDATE SET
            created_at = excluded.created_at,
            created_by = excluded.created_by,
            reason = excluded.reason,
            entry_json = excluded.entry_json
        "#,
        params![key, entry.source_ip, entry.principal_prefix, entry.path_prefix,
            entry.created_at.to_rfc3339(), entry.created_by, entry.reason, json],
    )?;

    Ok(())
}

pub fn query_tri_scoped_allowlist(sqlite_path: &str) -> Result<Vec<TriScopedAllowlistEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare("SELECT entry_json FROM tri_scoped_allowlist ORDER BY created_at DESC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: TriScopedAllowlistEntry = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_tri_scoped_allowlist(sqlite_path: &str, source_ip: &str, principal_prefix: &str, path_prefix: &str) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let key = format!("{}|{}|{}", source_ip, principal_prefix, path_prefix);
    let affected = conn.execute("DELETE FROM tri_scoped_allowlist WHERE allowlist_key = ?1", params![key])?;

    Ok(affected > 0)
}

pub fn upsert_restore_refusal_alert(sqlite_path: &str, item: &RestoreRefusalAlert) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let json = serde_json::to_string(item)?;

    conn.execute(
        r#"
        INSERT INTO restore_refusal_alerts
        (alert_id, created_at, bundle_id, severity, status, reason, stored_digest_sha256, recomputed_digest_sha256, latest_actor, alert_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(alert_id) DO UPDATE SET
            severity = excluded.severity,
            status = excluded.status,
            reason = excluded.reason,
            stored_digest_sha256 = excluded.stored_digest_sha256,
            recomputed_digest_sha256 = excluded.recomputed_digest_sha256,
            latest_actor = excluded.latest_actor,
            alert_json = excluded.alert_json
        "#,
        params![
            item.alert_id,
            item.created_at.to_rfc3339(),
            item.bundle_id,
            item.severity,
            item.status,
            item.reason,
            item.stored_digest_sha256,
            item.recomputed_digest_sha256,
            item.latest_actor,
            json
        ],
    )?;

    Ok(())
}

pub fn query_restore_refusal_alerts(sqlite_path: &str) -> Result<Vec<RestoreRefusalAlert>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        "SELECT alert_json FROM restore_refusal_alerts ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: RestoreRefusalAlert = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn get_restore_refusal_alert(sqlite_path: &str, alert_id: &str) -> Result<Option<RestoreRefusalAlert>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(None);
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        "SELECT alert_json FROM restore_refusal_alerts WHERE alert_id = ?1 LIMIT 1",
    )?;

    let mut rows = stmt.query(params![alert_id])?;
    if let Some(row) = rows.next()? {
        let json: String = row.get(0)?;
        let item: RestoreRefusalAlert = serde_json::from_str(&json)?;
        Ok(Some(item))
    } else {
        Ok(None)
    }
}

pub fn update_restore_refusal_alert_status(
    sqlite_path: &str,
    alert_id: &str,
    new_status: &str,
    actor: &str,
) -> Result<bool> {
    let mut item = match get_restore_refusal_alert(sqlite_path, alert_id)? {
        Some(item) => item,
        None => return Ok(false),
    };
    item.status = new_status.to_string();
    item.latest_actor = actor.to_string();
    upsert_restore_refusal_alert(sqlite_path, &item)?;
    Ok(true)
}

pub fn query_policy_timeline_page(
    sqlite_path: &str,
    filters: &crate::types::PolicyTimelineQuery,
) -> Result<crate::types::PolicyTimelinePage> {
    if !Path::new(sqlite_path).exists() {
        return Ok(crate::types::PolicyTimelinePage {
            items: Vec::new(),
            total: 0,
            limit: filters.limit.unwrap_or(50),
            offset: filters.offset.unwrap_or(0),
            sort_dir: filters.sort_dir.clone().unwrap_or_else(|| "desc".to_string()),
        });
    }

    let conn = Connection::open(sqlite_path)?;
    let mut where_sql = String::from(" WHERE 1=1");
    let mut values: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(actor) = &filters.actor {
        where_sql.push_str(" AND actor = ?");
        values.push(rusqlite::types::Value::Text(actor.clone()));
    }
    if let Some(action) = &filters.action {
        where_sql.push_str(" AND action = ?");
        values.push(rusqlite::types::Value::Text(action.clone()));
    }
    if let Some(target_contains) = &filters.target_contains {
        where_sql.push_str(" AND target LIKE ?");
        values.push(rusqlite::types::Value::Text(format!("%{}%", target_contains)));
    }
    if let Some(result) = &filters.result {
        where_sql.push_str(" AND result = ?");
        values.push(rusqlite::types::Value::Text(result.clone()));
    }

    let count_sql = format!("SELECT COUNT(*) FROM admin_audits{}", where_sql);
    let total: usize = conn.query_row(
        &count_sql,
        params_from_iter(values.iter()),
        |row| row.get::<_, i64>(0).map(|v| v as usize),
    )?;

    let sort_dir = match filters.sort_dir.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let mut page_values = values.clone();
    let page_sql = format!(
        "SELECT audit_json FROM admin_audits{} ORDER BY timestamp {} LIMIT ? OFFSET ?",
        where_sql, sort_dir,
    );
    page_values.push(rusqlite::types::Value::Integer(filters.limit.unwrap_or(50) as i64));
    page_values.push(rusqlite::types::Value::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&page_sql)?;
    let rows = stmt.query_map(params_from_iter(page_values.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let audit: crate::types::AdminAudit = serde_json::from_str(&row?)?;
        items.push(crate::types::PolicyTimelineEntry {
            timestamp: audit.timestamp,
            actor: audit.actor,
            action: audit.action,
            target: audit.target,
            result: audit.result,
            details: audit.details,
        });
    }

    Ok(crate::types::PolicyTimelinePage {
        items,
        total,
        limit: filters.limit.unwrap_or(50),
        offset: filters.offset.unwrap_or(0),
        sort_dir: sort_dir.to_ascii_lowercase(),
    })
}

pub fn count_restore_refusals_for_bundle(sqlite_path: &str, bundle_id: &str) -> Result<usize> {
    if !Path::new(sqlite_path).exists() {
        return Ok(0);
    }

    let conn = Connection::open(sqlite_path)?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM restore_refusals WHERE bundle_id = ?1",
        params![bundle_id],
        |row| row.get(0),
    )?;

    Ok(count as usize)
}

pub fn recent_response_contract_mismatch_events(
    sqlite_path: &str,
    limit: usize,
) -> Result<Vec<crate::types::SecurityEvent>> {
    let filters = crate::types::EventSearchFilters {
        source_ip: None,
        rule_id: Some("response.contract_mismatch".to_string()),
        severity: None,
        method: None,
        path_contains: None,
        since: None,
        until: None,
        limit: Some(limit),
        offset: Some(0),
    };
    query_security_events(sqlite_path, &filters)
}

pub fn persist_restore_refusal(sqlite_path: &str, item: &RestoreRefusalEvent) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let json = serde_json::to_string(item)?;

    conn.execute(
        r#"
        INSERT INTO restore_refusals
        (timestamp, actor, bundle_id, reason, stored_digest_sha256, recomputed_digest_sha256, refusal_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
        params![
            item.timestamp.to_rfc3339(),
            item.actor,
            item.bundle_id,
            item.reason,
            item.stored_digest_sha256,
            item.recomputed_digest_sha256,
            json
        ],
    )?;

    Ok(())
}

pub fn query_restore_refusals(sqlite_path: &str, limit: usize) -> Result<Vec<RestoreRefusalEvent>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT refusal_json
        FROM restore_refusals
        ORDER BY timestamp DESC
        LIMIT ?1
        "#,
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: RestoreRefusalEvent = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn query_policy_timeline_filtered(
    sqlite_path: &str,
    filters: &crate::types::PolicyTimelineFilters,
) -> Result<Vec<crate::types::PolicyTimelineEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut sql = String::from("SELECT audit_json FROM admin_audits WHERE 1=1");
    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(actor) = &filters.actor {
        sql.push_str(" AND actor = ?");
        params_vec.push(rusqlite::types::Value::Text(actor.clone()));
    }
    if let Some(action) = &filters.action {
        sql.push_str(" AND action = ?");
        params_vec.push(rusqlite::types::Value::Text(action.clone()));
    }
    if let Some(target_contains) = &filters.target_contains {
        sql.push_str(" AND target LIKE ?");
        params_vec.push(rusqlite::types::Value::Text(format!("%{}%", target_contains)));
    }
    if let Some(result) = &filters.result {
        sql.push_str(" AND result = ?");
        params_vec.push(rusqlite::types::Value::Text(result.clone()));
    }

    sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
    params_vec.push(rusqlite::types::Value::Integer(filters.limit.unwrap_or(50) as i64));
    params_vec.push(rusqlite::types::Value::Integer(filters.offset.unwrap_or(0) as i64));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(params_vec.iter()), |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let audit: crate::types::AdminAudit = serde_json::from_str(&row?)?;
        items.push(crate::types::PolicyTimelineEntry {
            timestamp: audit.timestamp,
            actor: audit.actor,
            action: audit.action,
            target: audit.target,
            result: audit.result,
            details: audit.details,
        });
    }

    Ok(items)
}

pub fn upsert_managed_spec_release_state(
    sqlite_path: &str,
    item: &ManagedSpecReleaseState,
) -> Result<()> {
    ensure_parent_dir(sqlite_path)?;
    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", item.method.to_ascii_uppercase(), item.normalized_path);
    let json = serde_json::to_string(item)?;

    conn.execute(
        r#"
        INSERT INTO managed_spec_release_state
        (route_key, method, normalized_path, channel, updated_at, updated_by, note, state_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(route_key) DO UPDATE SET
            channel = excluded.channel,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by,
            note = excluded.note,
            state_json = excluded.state_json
        "#,
        params![
            route_key,
            item.method,
            item.normalized_path,
            item.channel,
            item.updated_at.to_rfc3339(),
            item.updated_by,
            item.note,
            json
        ],
    )?;

    Ok(())
}

pub fn query_managed_spec_release_state(sqlite_path: &str) -> Result<Vec<ManagedSpecReleaseState>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        "SELECT state_json FROM managed_spec_release_state ORDER BY updated_at DESC",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let item: ManagedSpecReleaseState = serde_json::from_str(&row?)?;
        items.push(item);
    }

    Ok(items)
}

pub fn delete_managed_spec_release_state(
    sqlite_path: &str,
    method: &str,
    normalized_path: &str,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;
    let route_key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let affected = conn.execute(
        "DELETE FROM managed_spec_release_state WHERE route_key = ?1",
        params![route_key],
    )?;

    Ok(affected > 0)
}

pub fn tamper_policy_bundle_note(
    sqlite_path: &str,
    bundle_id: &str,
    note: Option<String>,
) -> Result<bool> {
    if !Path::new(sqlite_path).exists() {
        return Ok(false);
    }

    let conn = Connection::open(sqlite_path)?;

    let mut stmt = conn.prepare(
        "SELECT bundle_json FROM policy_bundles WHERE bundle_id = ?1 LIMIT 1",
    )?;

    let json_str: String = match stmt.query_row(params![bundle_id], |row| row.get(0)) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(false),
        Err(e) => return Err(e.into()),
    };

    let mut value: serde_json::Value = serde_json::from_str(&json_str)?;

    // Capture the original stored digest BEFORE any mutation.
    let original_digest = value
        .get("digest_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Mutate digest-covered policy content.
    value["note"] = serde_json::Value::String(
        note.unwrap_or_else(|| "tampered bundle for integrity testing".to_string()),
    );
    value["live_policy"]["global_rule_modes"]["phase14.tamper.marker"] =
        serde_json::Value::String("detect_only".to_string());

    // Restore the original digest so stored value stays "signed" with the old hash.
    value["digest_sha256"] = serde_json::Value::String(original_digest);

    let updated_json = serde_json::to_string(&value)?;
    let note_str = value
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or("tampered")
        .to_string();

    let affected = conn.execute(
        "UPDATE policy_bundles SET note = ?2, bundle_json = ?3 WHERE bundle_id = ?1",
        params![bundle_id, note_str, updated_json],
    )?;

    Ok(affected > 0)
}

pub fn recent_admin_timeline(sqlite_path: &str, limit: usize) -> Result<Vec<PolicyTimelineEntry>> {
    if !Path::new(sqlite_path).exists() {
        return Ok(Vec::new());
    }

    let conn = Connection::open(sqlite_path)?;
    let mut stmt = conn.prepare(
        r#"
        SELECT audit_json
        FROM admin_audits
        ORDER BY timestamp DESC
        LIMIT ?1
        "#,
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0))?;

    let mut items = Vec::new();
    for row in rows {
        let json = row?;
        let audit: crate::types::AdminAudit = serde_json::from_str(&json)?;
        items.push(crate::types::PolicyTimelineEntry {
            timestamp: audit.timestamp,
            actor: audit.actor,
            action: audit.action,
            target: audit.target,
            result: audit.result,
            details: audit.details,
        });
    }

    Ok(items)
}

pub fn delete_all_learned_routes(sqlite_path: &str) -> Result<usize> {
    if !Path::new(sqlite_path).exists() {
        return Ok(0);
    }

    let conn = Connection::open(sqlite_path)?;
    let removed = conn.execute("DELETE FROM learned_routes", [])?;
    Ok(removed)
}

pub fn metrics_snapshot(sqlite_path: &str) -> Result<StorageMetrics> {
    if !Path::new(sqlite_path).exists() {
        return Ok(StorageMetrics::default());
    }

    let conn = Connection::open(sqlite_path)?;

    let total_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events",
        [],
        |row| row.get(0),
    )?;

    let blocked_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events WHERE outcome LIKE 'reject:%'",
        [],
        |row| row.get(0),
    )?;

    let total_audits: i64 = conn.query_row(
        "SELECT COUNT(*) FROM admin_audits",
        [],
        |row| row.get(0),
    )?;

    let persisted_active_mitigations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM active_mitigations",
        [],
        |row| row.get(0),
    )?;

    let persisted_reputations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM reputations",
        [],
        |row| row.get(0),
    )?;

    let persisted_learned_routes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM learned_routes",
        [],
        |row| row.get(0),
    )?;

    let persisted_behavior_snapshots: i64 = conn.query_row(
        "SELECT COUNT(*) FROM behavior_snapshots",
        [],
        |row| row.get(0),
    )?;

    let approved_shadow_routes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM approved_shadow_routes",
        [],
        |row| row.get(0),
    )?;

    let promoted_spec_routes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM promoted_spec_routes",
        [],
        |row| row.get(0),
    )?;

    let managed_spec_routes: i64 = conn.query_row(
        "SELECT COUNT(*) FROM managed_spec_routes",
        [],
        |row| row.get(0),
    )?;

    let analyst_suppressions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM analyst_suppressions",
        [],
        |row| row.get(0),
    )?;

    let source_allowlist_entries: i64 = conn.query_row(
        "SELECT COUNT(*) FROM source_allowlist",
        [],
        |row| row.get(0),
    )?;

    let principal_allowlist_entries: i64 = conn.query_row(
        "SELECT COUNT(*) FROM principal_allowlist",
        [],
        |row| row.get(0),
    )?;

    let response_contracts: i64 = conn.query_row(
        "SELECT COUNT(*) FROM response_contracts",
        [],
        |row| row.get(0),
    )?;

    let policy_bundles: i64 = conn.query_row(
        "SELECT COUNT(*) FROM policy_bundles",
        [],
        |row| row.get(0),
    )?;

    let scoped_source_allowlist_entries: i64 = conn.query_row(
        "SELECT COUNT(*) FROM scoped_source_allowlist",
        [],
        |row| row.get(0),
    )?;

    let scoped_principal_allowlist_entries: i64 = conn.query_row(
        "SELECT COUNT(*) FROM scoped_principal_allowlist",
        [],
        |row| row.get(0),
    )?;

    let tri_scoped_allowlist_entries: i64 = conn.query_row(
        "SELECT COUNT(*) FROM tri_scoped_allowlist",
        [],
        |row| row.get(0),
    )?;

    let restore_refusals: i64 = conn.query_row(
        "SELECT COUNT(*) FROM restore_refusals",
        [],
        |row| row.get(0),
    )?;

    let managed_spec_release_states: i64 = conn.query_row(
        "SELECT COUNT(*) FROM managed_spec_release_state",
        [],
        |row| row.get(0),
    )?;

    let restore_refusal_alerts: i64 = conn.query_row(
        "SELECT COUNT(*) FROM restore_refusal_alerts",
        [],
        |row| row.get(0),
    )?;

    let critical_restore_refusal_alerts: i64 = conn.query_row(
        "SELECT COUNT(*) FROM restore_refusal_alerts WHERE severity = 'critical' AND status != 'resolved'",
        [],
        |row| row.get(0),
    )?;

    let latest_rule_ids: Option<String> = conn
        .query_row(
            r#"
            SELECT rule_ids
            FROM security_events
            WHERE rule_ids <> ''
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
            [],
            |row| row.get(0),
        )
        .ok();

    Ok(StorageMetrics {
        total_events,
        blocked_events,
        total_audits,
        latest_rule_ids: latest_rule_ids.unwrap_or_default(),
        persisted_active_mitigations,
        persisted_reputations,
        persisted_learned_routes,
        persisted_behavior_snapshots,
        approved_shadow_routes,
        promoted_spec_routes,
        managed_spec_routes,
        analyst_suppressions,
        source_allowlist_entries,
        principal_allowlist_entries,
        response_contracts,
        policy_bundles,
        scoped_source_allowlist_entries,
        scoped_principal_allowlist_entries,
        tri_scoped_allowlist_entries,
        restore_refusals,
        managed_spec_release_states,
        restore_refusal_alerts,
        critical_restore_refusal_alerts,
    })
}

#[derive(Debug, Default)]
pub struct StorageMetrics {
    pub total_events: i64,
    pub blocked_events: i64,
    pub total_audits: i64,
    pub latest_rule_ids: String,
    pub persisted_active_mitigations: i64,
    pub persisted_reputations: i64,
    pub persisted_learned_routes: i64,
    pub persisted_behavior_snapshots: i64,
    pub approved_shadow_routes: i64,
    pub promoted_spec_routes: i64,
    pub managed_spec_routes: i64,
    pub analyst_suppressions: i64,
    pub source_allowlist_entries: i64,
    pub principal_allowlist_entries: i64,
    pub response_contracts: i64,
    pub policy_bundles: i64,
    pub scoped_source_allowlist_entries: i64,
    pub scoped_principal_allowlist_entries: i64,
    pub tri_scoped_allowlist_entries: i64,
    pub restore_refusals: i64,
    pub managed_spec_release_states: i64,
    pub restore_refusal_alerts: i64,
    pub critical_restore_refusal_alerts: i64,
}

fn ensure_parent_dir(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn severity_rank(severity: &Severity) -> i32 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn rank_to_severity_name(rank: i32) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        _ => "low",
    }
}

fn normalize_rfc3339(input: &str) -> Result<String> {
    Ok(parse_rfc3339_to_utc(input)?.to_rfc3339())
}

fn parse_rfc3339_to_utc(input: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(input)?.with_timezone(&Utc))
}
