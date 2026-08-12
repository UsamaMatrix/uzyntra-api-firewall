use std::{collections::HashMap, net::IpAddr};

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    config::{RoutePolicyOverride, RouteRateLimitOverride},
    core, mitigation, storage,
    types::{
        ok, err, AdminAudit, AppState, DeleteRouteOverrideRequest, DeleteRouteRateLimitRequest,
        EventSearchFilters, SetGlobalRuleModeRequest, UpsertRouteOverrideRequest,
        UpsertRouteRateLimitRequest,
    },
};

#[derive(Debug, Deserialize, Default)]
pub struct BehaviorBaselineQuery {
    pub limit: Option<usize>,
}

pub async fn root() -> Json<Value> {
    Json(json!({
        "service": "api_firewall",
        "status": "running",
        "message": "Rust API Firewall public plane is up"
    }))
}

pub async fn public_healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "public"
    }))
}

pub async fn admin_healthz() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "admin",
        "auth_required": true
    }))
}

pub async fn admin_livez(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "plane": "admin",
        "public_health_enabled": state.config.server.admin_public_health_enabled
    }))
}

pub async fn readyz(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ready",
        "started_at": state.started_at,
        "upstream": state.config.proxy.upstream_base_url,
        "active_temp_blocks": state.mitigation_store.active_block_count(),
    }))
}

pub async fn get_config(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "server": state.config.server,
        "proxy": state.config.proxy,
        "security": state.config.security,
        "telemetry": state.config.telemetry,
        "storage": state.config.storage,
        "auth": {
            "enabled": state.config.auth.enabled,
            "header_name": state.config.auth.header_name,
            "protected_path_prefixes": state.config.auth.protected_path_prefixes,
            "api_keys_count": state.config.auth.api_keys.len(),
            "admin": {
                "enabled": state.config.auth.admin.enabled,
                "header_name": state.config.auth.admin.header_name
            }
        }
    }))
}

pub async fn effective_policy(State(state): State<AppState>) -> Json<Value> {
    let guard = state.policy_state.read().expect("policy_state poisoned");
    Json(json!(ok(json!({
        "global_rule_modes": guard.global_rule_modes,
        "route_overrides": guard.route_overrides,
        "route_rate_limits": guard.route_rate_limits
    }))))
}

pub async fn set_global_rule_mode(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SetGlobalRuleModeRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        guard.global_rule_modes.insert(body.rule_id.clone(), body.mode.clone());
    }

    audit(
        &state,
        actor,
        "set_global_rule_mode",
        body.rule_id.clone(),
        "updated",
        format!("mode={:?}", body.mode),
    );

    Json(json!(ok(json!({
        "rule_id": body.rule_id,
        "mode": body.mode
    }))))
}

pub async fn upsert_route_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpsertRouteOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        if let Some(existing) = guard
            .route_overrides
            .iter_mut()
            .find(|r| r.path_prefix == body.path_prefix)
        {
            existing.rule_modes = body.rule_modes.clone();
        } else {
            guard.route_overrides.push(RoutePolicyOverride {
                path_prefix: body.path_prefix.clone(),
                rule_modes: body.rule_modes.clone(),
            });
        }
    }

    audit(
        &state,
        actor,
        "upsert_route_override",
        body.path_prefix.clone(),
        "updated",
        "route override upserted".to_string(),
    );

    Json(json!(ok(body)))
}

pub async fn delete_route_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteRouteOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let removed = {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        let before = guard.route_overrides.len();
        guard.route_overrides.retain(|r| r.path_prefix != body.path_prefix);
        before != guard.route_overrides.len()
    };

    audit(
        &state,
        actor,
        "delete_route_override",
        body.path_prefix.clone(),
        if removed { "removed" } else { "not_found" },
        "route override delete attempted".to_string(),
    );

    Json(json!(ok(json!({
        "path_prefix": body.path_prefix,
        "removed": removed
    }))))
}

pub async fn upsert_route_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpsertRouteRateLimitRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        if let Some(existing) = guard
            .route_rate_limits
            .iter_mut()
            .find(|r| r.path_prefix == body.path_prefix)
        {
            existing.requests_per_window = body.requests_per_window;
            existing.window_secs = body.window_secs;
        } else {
            guard.route_rate_limits.push(RouteRateLimitOverride {
                path_prefix: body.path_prefix.clone(),
                requests_per_window: body.requests_per_window,
                window_secs: body.window_secs,
            });
        }
    }

    audit(
        &state,
        actor,
        "upsert_route_rate_limit",
        body.path_prefix.clone(),
        "updated",
        format!(
            "requests_per_window={}; window_secs={}",
            body.requests_per_window, body.window_secs
        ),
    );

    Json(json!(ok(body)))
}

pub async fn delete_route_rate_limit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteRouteRateLimitRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let removed = {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        let before = guard.route_rate_limits.len();
        guard.route_rate_limits.retain(|r| r.path_prefix != body.path_prefix);
        before != guard.route_rate_limits.len()
    };

    audit(
        &state,
        actor,
        "delete_route_rate_limit",
        body.path_prefix.clone(),
        if removed { "removed" } else { "not_found" },
        "route rate limit delete attempted".to_string(),
    );

    Json(json!(ok(json!({
        "path_prefix": body.path_prefix,
        "removed": removed
    }))))
}

pub async fn demo_recommendations() -> Json<Value> {
    let recommendations = mitigation::demo_recommendations();
    let commands: Vec<_> = recommendations
        .iter()
        .filter_map(mitigation::recommendation_to_command)
        .collect();

    Json(json!(ok(json!({
        "recommendations": recommendations,
        "commands": commands
    }))))
}

pub async fn demo_one_click_commands() -> Json<Value> {
    let mut block_params = HashMap::new();
    block_params.insert("ttl_secs".to_string(), "900".to_string());
    block_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut unblock_params = HashMap::new();
    unblock_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut reset_rep_params = HashMap::new();
    reset_rep_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    let mut clear_params = HashMap::new();
    clear_params.insert("source_ip".to_string(), "127.0.0.1".to_string());

    Json(json!(ok(json!({
        "commands": [
            {
                "kind": "BlockIpTemporary",
                "title": "Temporarily block source IP",
                "rationale": "Use for repeated exploit probes.",
                "reversible": true,
                "parameters": block_params
            },
            {
                "kind": "UnblockIp",
                "title": "Remove temporary block",
                "rationale": "Use when analyst confirms the source should be restored.",
                "reversible": true,
                "parameters": unblock_params
            },
            {
                "kind": "ResetReputation",
                "title": "Reset source reputation",
                "rationale": "Use after analyst review clears the source.",
                "reversible": false,
                "parameters": reset_rep_params
            },
            {
                "kind": "ResetReputation",
                "title": "Clear source state",
                "rationale": "Clears both reputation and active temporary block for the source.",
                "reversible": false,
                "parameters": clear_params
            }
        ]
    }))))
}

pub async fn list_active_blocks(State(state): State<AppState>) -> Json<Value> {
    let blocks = state.mitigation_store.list_active_blocks();

    let items: Vec<_> = blocks
        .into_iter()
        .map(|b| {
            json!({
                "action_id": b.action_id,
                "source_ip": b.source_ip.to_string(),
                "action": b.action,
                "created_at": b.created_at,
                "expires_at": b.expires_at,
                "reason": b.reason
            })
        })
        .collect();

    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn list_reputations(State(state): State<AppState>) -> Json<Value> {
    let items = state.mitigation_store.list_reputations();
    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn get_reputation(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Json<Value> {
    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let rep = state.mitigation_store.get_reputation(parsed);
            Json(json!(ok(json!({ "item": rep }))))
        }
        Err(_) => Json(json!(err::<Value>("invalid IP address"))),
    }
}

pub async fn unblock_ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match ip.parse::<IpAddr>() {
        Ok(parsed) => {
            let removed = state.mitigation_store.unblock_ip(parsed);

            if removed {
                if let Err(e) =
                    storage::delete_active_mitigation(&state.config.storage.sqlite_path, &parsed.to_string())
                {
                    tracing::error!(error = %e, "failed to delete active mitigation from SQLite");
                }
            }

            audit(
                &state,
                actor,
                "unblock_ip",
                parsed.to_string(),
                if removed { "removed" } else { "not_found" },
                "manual unblock via admin API".to_string(),
            );

            Json(json!(ok(json!({
                "source_ip": parsed.to_string(),
                "removed": removed
            }))))
        }
        Err(_) => Json(json!(err::<Value>("invalid IP address"))),
    }
}

pub async fn clear_source(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let parsed = match ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return Json(json!(err::<Value>("invalid IP address"))),
    };

    match mitigation::clear_source_state(&state, parsed) {
        Ok((block_removed, reputation_removed)) => {
            audit(
                &state,
                actor,
                "clear_source",
                parsed.to_string(),
                "updated",
                format!("block_removed={block_removed}; reputation_removed={reputation_removed}"),
            );

            Json(json!(ok(json!({
                "source_ip": parsed.to_string(),
                "block_removed": block_removed,
                "reputation_removed": reputation_removed
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn manual_block_ip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ManualBlockRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let parsed_ip = match body.source_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Json(json!(err::<Value>("invalid IP address")));
        }
    };

    let ttl_secs = body.ttl_secs.unwrap_or(state.config.security.temp_ban_secs);
    let reason = body
        .reason
        .unwrap_or_else(|| "manual block via admin API".to_string());

    match mitigation::apply_manual_block(&state, parsed_ip, ttl_secs, reason.clone()) {
        Ok(mit) => {
            audit(
                &state,
                actor,
                "manual_block_ip",
                parsed_ip.to_string(),
                "applied",
                format!("ttl_secs={ttl_secs}; reason={reason}"),
            );

            Json(json!(ok(json!({
                "action_id": mit.action_id,
                "source_ip": mit.source_ip.to_string(),
                "expires_at": mit.expires_at,
                "reason": mit.reason
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn reset_reputation(
    State(state): State<AppState>,
    Path(ip): Path<String>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let parsed = match ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Json(json!(err::<Value>("invalid IP address")));
        }
    };

    match mitigation::reset_reputation_for_ip(&state, parsed) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "reset_reputation",
                parsed.to_string(),
                if removed { "removed" } else { "not_found" },
                "manual reputation reset via admin API".to_string(),
            );

            Json(json!(ok(json!({
                "source_ip": parsed.to_string(),
                "removed": removed
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn response_contracts(State(state): State<AppState>) -> Json<Value> {
    match storage::query_response_contracts(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_response_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertResponseContractRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::ResponseContract {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path.clone(),
        expected_status: body.expected_status,
        expected_content_type_prefix: body.expected_content_type_prefix.clone(),
        required_headers: body.required_headers.clone(),
        approved_at: chrono::Utc::now(),
        approved_by: actor.clone(),
        note: body.note.clone(),
    };

    match storage::upsert_response_contract(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "upsert_response_contract",
                format!("{} {}", item.method, item.normalized_path),
                "updated",
                "response contract upserted".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_response_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteResponseContractRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_response_contract(
        &state.config.storage.sqlite_path,
        &body.method,
        &body.normalized_path,
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_response_contract",
                format!("{} {}", body.method, body.normalized_path),
                if removed { "removed" } else { "not_found" },
                "response contract delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "method": body.method.to_ascii_uppercase(),
                "normalized_path": body.normalized_path
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn policy_bundles(State(state): State<AppState>) -> Json<Value> {
    match storage::query_policy_bundles(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn save_policy_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::SavePolicyBundleRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let live_policy = crate::core::export_live_policy_state(&state);
    let digest = crate::core::compute_live_policy_digest(&live_policy);

    let bundle = crate::types::PolicyBundle {
        bundle_id: crate::core::make_policy_bundle_id(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        note: body.note.clone(),
        digest_sha256: digest.clone(),
        live_policy,
    };

    match storage::save_policy_bundle(&state.config.storage.sqlite_path, &bundle) {
        Ok(()) => {
            audit(&state, actor, "save_policy_bundle", bundle.bundle_id.clone(), "created",
                format!("signed policy bundle saved; digest={digest}"));
            Json(json!(ok(json!({
                "bundle_id": bundle.bundle_id,
                "created_at": bundle.created_at,
                "created_by": bundle.created_by,
                "note": bundle.note,
                "digest_sha256": digest
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn restore_policy_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::RestorePolicyBundleRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::get_policy_bundle(&state.config.storage.sqlite_path, &body.bundle_id) {
        Ok(Some(bundle)) => {
            let recomputed = crate::core::compute_live_policy_digest(&bundle.live_policy);
            if recomputed != bundle.digest_sha256 {
                crate::core::record_restore_refusal(
                    &state,
                    actor.clone(),
                    bundle.bundle_id.clone(),
                    "policy bundle digest mismatch".to_string(),
                    bundle.digest_sha256.clone(),
                    recomputed.clone(),
                );
                let refusal_count = storage::count_restore_refusals_for_bundle(
                    &state.config.storage.sqlite_path,
                    &bundle.bundle_id,
                ).unwrap_or(1);
                let alert = crate::types::RestoreRefusalAlert {
                    alert_id: format!("alert-{}", uuid::Uuid::new_v4()),
                    created_at: chrono::Utc::now(),
                    bundle_id: bundle.bundle_id.clone(),
                    severity: crate::core::restore_refusal_severity_for_count(refusal_count),
                    status: "open".to_string(),
                    reason: "policy bundle digest mismatch".to_string(),
                    stored_digest_sha256: bundle.digest_sha256.clone(),
                    recomputed_digest_sha256: recomputed,
                    latest_actor: actor.clone(),
                };
                let _ = storage::upsert_restore_refusal_alert(&state.config.storage.sqlite_path, &alert);
                audit(
                    &state,
                    actor,
                    "restore_policy_bundle",
                    body.bundle_id,
                    "refused",
                    "policy bundle restore refused due to digest mismatch".to_string(),
                );
                return Json(json!(err::<Value>("policy bundle digest mismatch")));
            }
            {
                let mut guard = state.policy_state.write().expect("policy_state poisoned");
                guard.global_rule_modes = bundle.live_policy.global_rule_modes.clone();
                guard.route_overrides = bundle.live_policy.route_overrides.clone();
                guard.route_rate_limits = bundle.live_policy.route_rate_limits.clone();
                guard.route_behavior_overrides = bundle.live_policy.route_behavior_overrides.clone();
            }
            audit(&state, actor, "restore_policy_bundle", body.bundle_id, "updated",
                format!("signed policy bundle restored; digest={}", bundle.digest_sha256));
            Json(json!(ok(bundle)))
        }
        Ok(None) => Json(json!(err::<Value>("policy bundle not found"))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn latest_policy_diff(State(state): State<AppState>) -> Json<Value> {
    match storage::query_policy_bundles(&state.config.storage.sqlite_path) {
        Ok(items) => {
            if let Some(bundle) = items.first() {
                let live = crate::core::export_live_policy_state(&state);
                let diff = crate::core::compute_policy_diff(
                    &live,
                    &bundle.live_policy,
                    Some(bundle.bundle_id.clone()),
                );
                Json(json!(ok(diff)))
            } else {
                Json(json!(ok(crate::types::PolicyDiffResult {
                    compared_at: chrono::Utc::now(),
                    bundle_id: None,
                    has_changes: false,
                    global_rule_modes_changed: false,
                    route_overrides_changed: false,
                    route_rate_limits_changed: false,
                    route_behavior_overrides_changed: false,
                })))
            }
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn tri_scoped_allowlist(State(state): State<AppState>) -> Json<Value> {
    match storage::query_tri_scoped_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({ "count": items.len(), "items": items })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_tri_scoped_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertTriScopedAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let item = crate::types::TriScopedAllowlistEntry {
        source_ip: body.source_ip.clone(),
        principal_prefix: body.principal_prefix.clone(),
        path_prefix: body.path_prefix.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };
    match storage::upsert_tri_scoped_allowlist(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(&state, actor, "upsert_tri_scoped_allowlist",
                format!("{} {} {}", item.source_ip, item.principal_prefix, item.path_prefix),
                "updated", "tri-scoped allowlist entry upserted".to_string());
            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_tri_scoped_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteTriScopedAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::delete_tri_scoped_allowlist(
        &state.config.storage.sqlite_path,
        &body.source_ip, &body.principal_prefix, &body.path_prefix,
    ) {
        Ok(removed) => {
            audit(&state, actor, "delete_tri_scoped_allowlist",
                format!("{} {} {}", body.source_ip, body.principal_prefix, body.path_prefix),
                if removed { "removed" } else { "not_found" },
                "tri-scoped allowlist entry delete attempted".to_string());
            Json(json!(ok(json!({
                "removed": removed,
                "source_ip": body.source_ip,
                "principal_prefix": body.principal_prefix,
                "path_prefix": body.path_prefix
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn verify_policy_bundle_latest(State(state): State<AppState>) -> Json<Value> {
    let live = crate::core::export_live_policy_state(&state);
    match storage::query_policy_bundles(&state.config.storage.sqlite_path) {
        Ok(items) => {
            if let Some(bundle) = items.first() {
                let result = crate::core::verify_policy_bundle(bundle, &live);
                Json(json!(ok(result)))
            } else {
                Json(json!(err::<Value>("no policy bundle available")))
            }
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn verify_policy_bundle_by_id(
    State(state): State<AppState>,
    Json(body): Json<crate::types::RestorePolicyBundleRequest>,
) -> Json<Value> {
    let live = crate::core::export_live_policy_state(&state);
    match storage::get_policy_bundle(&state.config.storage.sqlite_path, &body.bundle_id) {
        Ok(Some(bundle)) => {
            let result = crate::core::verify_policy_bundle(&bundle, &live);
            Json(json!(ok(result)))
        }
        Ok(None) => Json(json!(err::<Value>("policy bundle not found"))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn tamper_policy_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::TamperPolicyBundleRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::tamper_policy_bundle_note(
        &state.config.storage.sqlite_path,
        &body.bundle_id,
        body.note.clone(),
    ) {
        Ok(true) => {
            audit(
                &state,
                actor,
                "tamper_policy_bundle",
                body.bundle_id.clone(),
                "updated",
                "policy bundle tampered for integrity testing".to_string(),
            );
            Json(json!(ok(json!({
                "bundle_id": body.bundle_id,
                "tampered": true,
                "tamper_mode": "live_policy_mutated_without_digest_recompute"
            }))))
        }
        Ok(false) => Json(json!(err::<Value>("policy bundle not found"))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn approve_response_contract_from_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ApproveContractFromEventRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let filters = crate::types::EventSearchFilters {
        source_ip: None,
        rule_id: None,
        severity: None,
        method: None,
        path_contains: None,
        since: None,
        until: None,
        limit: Some(200),
        offset: Some(0),
    };

    match storage::query_security_events(&state.config.storage.sqlite_path, &filters) {
        Ok(events) => {
            if let Some(event) = events.into_iter().find(|e| e.request_id == body.request_id) {
                match crate::core::build_response_contract_from_mismatch_event(
                    &event,
                    actor.clone(),
                    body.note.clone(),
                ) {
                    Some(contract) => {
                        match storage::upsert_response_contract(&state.config.storage.sqlite_path, &contract) {
                            Ok(()) => {
                                audit(
                                    &state,
                                    actor,
                                    "approve_response_contract_from_event",
                                    body.request_id,
                                    "updated",
                                    "response contract approved from recent mismatch event".to_string(),
                                );
                                Json(json!(ok(contract)))
                            }
                            Err(e) => Json(json!(err::<Value>(e.to_string()))),
                        }
                    }
                    None => Json(json!(err::<Value>("event is not a response.contract_mismatch"))),
                }
            } else {
                Json(json!(err::<Value>("request_id not found")))
            }
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn policy_timeline_page(
    State(state): State<AppState>,
    Query(filters): Query<crate::types::PolicyTimelineQuery>,
) -> Json<Value> {
    match storage::query_policy_timeline_page(&state.config.storage.sqlite_path, &filters) {
        Ok(page) => Json(json!(ok(page))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn restore_refusal_alerts(State(state): State<AppState>) -> Json<Value> {
    match storage::query_restore_refusal_alerts(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn acknowledge_restore_refusal_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::AcknowledgeRestoreRefusalAlertRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::update_restore_refusal_alert_status(
        &state.config.storage.sqlite_path,
        &body.alert_id,
        "acknowledged",
        &actor,
    ) {
        Ok(true) => {
            audit(&state, actor, "acknowledge_restore_refusal_alert", body.alert_id,
                "updated", "restore refusal alert acknowledged".to_string());
            Json(json!(ok(json!({"acknowledged": true}))))
        }
        Ok(false) => Json(json!(err::<Value>("restore refusal alert not found"))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn resolve_restore_refusal_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ResolveRestoreRefusalAlertRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::update_restore_refusal_alert_status(
        &state.config.storage.sqlite_path,
        &body.alert_id,
        "resolved",
        &actor,
    ) {
        Ok(true) => {
            audit(&state, actor, "resolve_restore_refusal_alert", body.alert_id,
                "updated", "restore refusal alert resolved".to_string());
            Json(json!(ok(json!({"resolved": true}))))
        }
        Ok(false) => Json(json!(err::<Value>("restore refusal alert not found"))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn promote_managed_spec_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::PromoteManagedSpecReleaseRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let guard = crate::core::evaluate_release_guard(
        &state,
        &body.method,
        &body.normalized_path,
        &body.target_channel,
    );
    if !guard.allowed {
        return Json(json!(err::<Value>(format!(
            "release guard blocked promotion: {}",
            guard.reasons.join("; ")
        ))));
    }

    let current_items = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let current = current_items.iter().find(|item| {
        item.method.eq_ignore_ascii_case(&body.method)
            && item.normalized_path == body.normalized_path
    }).map(|item| item.channel.as_str());

    if !crate::core::is_valid_release_transition(current, &body.target_channel) {
        return Json(json!(err::<Value>("invalid release-state transition")));
    }

    let next = crate::types::ManagedSpecReleaseState {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path,
        channel: body.target_channel,
        updated_at: chrono::Utc::now(),
        updated_by: actor.clone(),
        note: body.note,
    };

    match storage::upsert_managed_spec_release_state(&state.config.storage.sqlite_path, &next) {
        Ok(()) => {
            audit(&state, actor, "promote_managed_spec_release",
                format!("{} {}", next.method, next.normalized_path),
                "updated", format!("release channel moved to {}", next.channel));
            Json(json!(ok(next)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn export_kong_inventory(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_kong_inventory(&state))))
}

pub async fn export_envoy_inventory(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_envoy_inventory(&state))))
}

pub async fn contract_recommendations(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::build_contract_recommendations(&state))))
}

pub async fn export_api_gateway_policy(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_api_gateway_policy_inventory(&state))))
}

pub async fn export_manifest(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_manifest(&state))))
}

pub async fn policy_timeline_filtered(
    State(state): State<AppState>,
    Query(filters): Query<crate::types::PolicyTimelineFilters>,
) -> Json<Value> {
    match storage::query_policy_timeline_filtered(&state.config.storage.sqlite_path, &filters) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items,
            "limit": filters.limit.unwrap_or(50),
            "offset": filters.offset.unwrap_or(0),
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn restore_refusals(State(state): State<AppState>) -> Json<Value> {
    match storage::query_restore_refusals(&state.config.storage.sqlite_path, 50) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn managed_spec_release_state(State(state): State<AppState>) -> Json<Value> {
    match storage::query_managed_spec_release_state(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_managed_spec_release_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertManagedSpecReleaseStateRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let item = crate::types::ManagedSpecReleaseState {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path,
        channel: body.channel,
        updated_at: chrono::Utc::now(),
        updated_by: actor.clone(),
        note: body.note,
    };
    match storage::upsert_managed_spec_release_state(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(&state, actor, "upsert_managed_spec_release_state",
                format!("{} {}", item.method, item.normalized_path),
                "updated", format!("release channel set to {}", item.channel));
            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_managed_spec_release_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteManagedSpecReleaseStateRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::delete_managed_spec_release_state(
        &state.config.storage.sqlite_path,
        &body.method,
        &body.normalized_path,
    ) {
        Ok(removed) => {
            audit(&state, actor, "delete_managed_spec_release_state",
                format!("{} {}", body.method, body.normalized_path),
                if removed { "removed" } else { "not_found" },
                "managed spec release state delete attempted".to_string());
            Json(json!(ok(json!({
                "removed": removed,
                "method": body.method.to_ascii_uppercase(),
                "normalized_path": body.normalized_path
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn export_gateway_variant(
    State(state): State<AppState>,
    Query(req): Query<crate::types::GatewayExportVariantRequest>,
) -> Json<Value> {
    match req.variant.as_str() {
        "gateway-routing-only" => Json(json!(ok(crate::core::export_gateway_routing_only_inventory(&state)))),
        "gateway-enforcement" => Json(json!(ok(crate::core::export_gateway_enforcement_inventory(&state)))),
        _ => Json(json!(ok(crate::core::export_gateway_managed_spec_inventory(&state)))),
    }
}

pub async fn policy_timeline(State(state): State<AppState>) -> Json<Value> {
    match storage::recent_admin_timeline(&state.config.storage.sqlite_path, 50) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn export_gateway_managed_spec_inventory(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_gateway_managed_spec_inventory(&state))))
}

pub async fn export_enforcement_managed_spec_inventory(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_enforcement_managed_spec_inventory(&state))))
}

pub async fn approve_response_contract(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ApproveContractMismatchRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let contract = crate::core::build_response_contract_from_request(actor.clone(), body);
    match storage::upsert_response_contract(&state.config.storage.sqlite_path, &contract) {
        Ok(()) => {
            audit(&state, actor, "approve_response_contract",
                format!("{} {}", contract.method, contract.normalized_path),
                "updated", "response contract approved from analyst shortcut".to_string());
            Json(json!(ok(contract)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn scoped_source_allowlist(State(state): State<AppState>) -> Json<Value> {
    match storage::query_scoped_source_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({ "count": items.len(), "items": items })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_scoped_source_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertScopedSourceAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let item = crate::types::ScopedSourceAllowlistEntry {
        source_ip: body.source_ip.clone(),
        path_prefix: body.path_prefix.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };
    match storage::upsert_scoped_source_allowlist(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(&state, actor, "upsert_scoped_source_allowlist",
                format!("{} {}", item.source_ip, item.path_prefix), "updated",
                "scoped source allowlist entry upserted".to_string());
            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_scoped_source_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteScopedSourceAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::delete_scoped_source_allowlist(&state.config.storage.sqlite_path, &body.source_ip, &body.path_prefix) {
        Ok(removed) => {
            audit(&state, actor, "delete_scoped_source_allowlist",
                format!("{} {}", body.source_ip, body.path_prefix),
                if removed { "removed" } else { "not_found" },
                "scoped source allowlist entry delete attempted".to_string());
            Json(json!(ok(json!({ "removed": removed, "source_ip": body.source_ip, "path_prefix": body.path_prefix }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn scoped_principal_allowlist(State(state): State<AppState>) -> Json<Value> {
    match storage::query_scoped_principal_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({ "count": items.len(), "items": items })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_scoped_principal_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertScopedPrincipalAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let item = crate::types::ScopedPrincipalAllowlistEntry {
        principal_prefix: body.principal_prefix.clone(),
        path_prefix: body.path_prefix.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };
    match storage::upsert_scoped_principal_allowlist(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(&state, actor, "upsert_scoped_principal_allowlist",
                format!("{} {}", item.principal_prefix, item.path_prefix), "updated",
                "scoped principal allowlist entry upserted".to_string());
            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_scoped_principal_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteScopedPrincipalAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    match storage::delete_scoped_principal_allowlist(&state.config.storage.sqlite_path, &body.principal_prefix, &body.path_prefix) {
        Ok(removed) => {
            audit(&state, actor, "delete_scoped_principal_allowlist",
                format!("{} {}", body.principal_prefix, body.path_prefix),
                if removed { "removed" } else { "not_found" },
                "scoped principal allowlist entry delete attempted".to_string());
            Json(json!(ok(json!({ "removed": removed, "principal_prefix": body.principal_prefix, "path_prefix": body.path_prefix }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn export_managed_spec_inventory(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_managed_spec_inventory(&state))))
}

pub async fn source_allowlist(State(state): State<AppState>) -> Json<Value> {
    match storage::query_source_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_source_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertSourceAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::SourceAllowlistEntry {
        source_ip: body.source_ip.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };

    match storage::upsert_source_allowlist(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "upsert_source_allowlist",
                item.source_ip.clone(),
                "updated",
                "source allowlist entry upserted".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_source_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteSourceAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_source_allowlist(&state.config.storage.sqlite_path, &body.source_ip) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_source_allowlist",
                body.source_ip.clone(),
                if removed { "removed" } else { "not_found" },
                "source allowlist entry delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "source_ip": body.source_ip
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn principal_allowlist(State(state): State<AppState>) -> Json<Value> {
    match storage::query_principal_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_principal_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertPrincipalAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::PrincipalAllowlistEntry {
        principal_prefix: body.principal_prefix.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };

    match storage::upsert_principal_allowlist(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "upsert_principal_allowlist",
                item.principal_prefix.clone(),
                "updated",
                "principal allowlist entry upserted".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_principal_allowlist(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeletePrincipalAllowlistRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_principal_allowlist(
        &state.config.storage.sqlite_path,
        &body.principal_prefix,
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_principal_allowlist",
                body.principal_prefix.clone(),
                if removed { "removed" } else { "not_found" },
                "principal allowlist entry delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "principal_prefix": body.principal_prefix
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn export_live_policy(State(state): State<AppState>) -> Json<Value> {
    Json(json!(ok(crate::core::export_live_policy_state(&state))))
}

pub async fn import_live_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::LivePolicyImportRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        guard.global_rule_modes = body.global_rule_modes.clone();
        guard.route_overrides = body.route_overrides.clone();
        guard.route_rate_limits = body.route_rate_limits.clone();
        guard.route_behavior_overrides = body.route_behavior_overrides.clone();
    }

    audit(
        &state,
        actor,
        "import_live_policy",
        "policy_state".to_string(),
        "updated",
        "live policy imported".to_string(),
    );

    Json(json!(ok(body)))
}

pub async fn managed_spec_routes(State(state): State<AppState>) -> Json<Value> {
    match storage::query_managed_spec_routes(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn promote_to_managed_spec(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::PromoteToManagedSpecRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::ManagedSpecRoute {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path.clone(),
        managed_at: chrono::Utc::now(),
        managed_by: actor.clone(),
        auth_required: body.auth_required,
        note: body.note.clone(),
    };

    match storage::upsert_managed_spec_route(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            let _ = storage::delete_promoted_spec_route(
                &state.config.storage.sqlite_path,
                &item.method,
                &item.normalized_path,
            );
            let _ = storage::replace_learned_routes(
                &state.config.storage.sqlite_path,
                &core::discover_shadow_apis_filtered(&state),
            );

            audit(
                &state,
                actor,
                "promote_to_managed_spec",
                format!("{} {}", item.method, item.normalized_path),
                "updated",
                "promoted spec candidate moved to managed spec inventory".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_managed_spec_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::PromoteToManagedSpecRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_managed_spec_route(
        &state.config.storage.sqlite_path,
        &body.method,
        &body.normalized_path,
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_managed_spec_route",
                format!("{} {}", body.method, body.normalized_path),
                if removed { "removed" } else { "not_found" },
                "managed spec route delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "method": body.method.to_ascii_uppercase(),
                "normalized_path": body.normalized_path
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn analyst_suppressions(State(state): State<AppState>) -> Json<Value> {
    match storage::query_analyst_suppressions(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn upsert_analyst_suppression(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertSuppressionRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::AnalystSuppression {
        rule_id: body.rule_id.clone(),
        path_prefix: body.path_prefix.clone(),
        created_at: chrono::Utc::now(),
        created_by: actor.clone(),
        reason: body.reason.clone(),
    };

    match storage::upsert_analyst_suppression(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "upsert_analyst_suppression",
                format!("{} {:?}", item.rule_id, item.path_prefix),
                "updated",
                "analyst suppression upserted".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_analyst_suppression(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteSuppressionRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_analyst_suppression(
        &state.config.storage.sqlite_path,
        &body.rule_id,
        body.path_prefix.as_deref(),
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_analyst_suppression",
                format!("{} {:?}", body.rule_id, body.path_prefix),
                if removed { "removed" } else { "not_found" },
                "analyst suppression delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "rule_id": body.rule_id,
                "path_prefix": body.path_prefix
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn list_route_behavior_overrides(State(state): State<AppState>) -> Json<Value> {
    let guard = state.policy_state.read().expect("policy_state poisoned");
    Json(json!(ok(json!({
        "count": guard.route_behavior_overrides.len(),
        "items": guard.route_behavior_overrides
    }))))
}

pub async fn upsert_route_behavior_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::UpsertRouteBehaviorOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        if let Some(existing) = guard
            .route_behavior_overrides
            .iter_mut()
            .find(|r| r.path_prefix == body.path_prefix)
        {
            existing.warmup_min_samples = body.warmup_min_samples;
            existing.object_enumeration_threshold = body.object_enumeration_threshold;
            existing.object_window_secs = body.object_window_secs;
        } else {
            guard.route_behavior_overrides.push(crate::config::RouteBehaviorOverride {
                path_prefix: body.path_prefix.clone(),
                warmup_min_samples: body.warmup_min_samples,
                object_enumeration_threshold: body.object_enumeration_threshold,
                object_window_secs: body.object_window_secs,
            });
        }
    }

    audit(
        &state,
        actor,
        "upsert_route_behavior_override",
        body.path_prefix.clone(),
        "updated",
        "route behavior override upserted".to_string(),
    );

    Json(json!(ok(body)))
}

pub async fn delete_route_behavior_override(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::DeleteRouteBehaviorOverrideRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let removed = {
        let mut guard = state.policy_state.write().expect("policy_state poisoned");
        let before = guard.route_behavior_overrides.len();
        guard.route_behavior_overrides.retain(|r| r.path_prefix != body.path_prefix);
        before != guard.route_behavior_overrides.len()
    };

    audit(
        &state,
        actor,
        "delete_route_behavior_override",
        body.path_prefix.clone(),
        if removed { "removed" } else { "not_found" },
        "route behavior override delete attempted".to_string(),
    );

    Json(json!(ok(json!({
        "path_prefix": body.path_prefix,
        "removed": removed
    }))))
}

pub async fn promoted_spec_routes(State(state): State<AppState>) -> Json<Value> {
    match storage::query_promoted_spec_routes(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn promote_shadow_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::PromoteShadowRouteRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::PromotedSpecRoute {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path.clone(),
        promoted_at: chrono::Utc::now(),
        promoted_by: actor.clone(),
        source: "shadow_route".to_string(),
        note: body.note.clone(),
    };

    match storage::upsert_promoted_spec_route(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            let _ = storage::delete_approved_shadow_route(
                &state.config.storage.sqlite_path,
                &item.method,
                &item.normalized_path,
            );
            let _ = storage::replace_learned_routes(
                &state.config.storage.sqlite_path,
                &core::discover_shadow_apis_filtered(&state),
            );

            audit(
                &state,
                actor,
                "promote_shadow_route",
                format!("{} {}", item.method, item.normalized_path),
                "updated",
                "approved shadow route promoted to spec candidate inventory".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_promoted_spec_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::PromoteShadowRouteRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_promoted_spec_route(
        &state.config.storage.sqlite_path,
        &body.method,
        &body.normalized_path,
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_promoted_spec_route",
                format!("{} {}", body.method, body.normalized_path),
                if removed { "removed" } else { "not_found" },
                "promoted spec route delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "method": body.method.to_ascii_uppercase(),
                "normalized_path": body.normalized_path
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn raw_shadow_routes(State(state): State<AppState>) -> Json<Value> {
    let items = core::discover_shadow_apis_raw(&state);
    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn filtered_shadow_routes(State(state): State<AppState>) -> Json<Value> {
    let items = core::discover_shadow_apis_filtered(&state);
    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn persist_behavior_snapshots(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let items = state.rate_limiter.snapshot_behavior_persistable(500);

    match storage::replace_behavior_snapshots(&state.config.storage.sqlite_path, &items) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "persist_behavior_snapshots",
                "behavior_snapshots".to_string(),
                "updated",
                format!("persisted={}", items.len()),
            );

            Json(json!(ok(json!({
                "persisted": items.len()
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn persisted_behavior_snapshots(State(state): State<AppState>) -> Json<Value> {
    match storage::query_behavior_snapshots(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn approved_shadow_routes(State(state): State<AppState>) -> Json<Value> {
    match storage::query_approved_shadow_routes(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn approve_shadow_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ApproveShadowRouteRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let item = crate::types::ApprovedShadowRoute {
        method: body.method.to_ascii_uppercase(),
        normalized_path: body.normalized_path,
        approved_at: chrono::Utc::now(),
        approved_by: actor.clone(),
        note: body.note,
    };

    match storage::upsert_approved_shadow_route(&state.config.storage.sqlite_path, &item) {
        Ok(()) => {
            audit(
                &state,
                actor,
                "approve_shadow_route",
                format!("{} {}", item.method, item.normalized_path),
                "updated",
                "shadow route approved".to_string(),
            );

            Json(json!(ok(item)))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn delete_approved_shadow_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::types::ApproveShadowRouteRequest>,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match storage::delete_approved_shadow_route(
        &state.config.storage.sqlite_path,
        &body.method,
        &body.normalized_path,
    ) {
        Ok(removed) => {
            audit(
                &state,
                actor,
                "delete_approved_shadow_route",
                format!("{} {}", body.method, body.normalized_path),
                if removed { "removed" } else { "not_found" },
                "approved shadow route delete attempted".to_string(),
            );

            Json(json!(ok(json!({
                "removed": removed,
                "method": body.method.to_ascii_uppercase(),
                "normalized_path": body.normalized_path
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn clear_behavior_baselines(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);
    let removed = state.rate_limiter.clear_behavior_state();

    audit(
        &state,
        actor,
        "clear_behavior_baselines",
        "behavior_state".to_string(),
        "updated",
        format!("removed={removed}"),
    );

    Json(json!(ok(json!({
        "removed": removed
    }))))
}

pub async fn clear_shadow_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    let memory_removed = core::clear_learned_routes();

    match storage::delete_all_learned_routes(&state.config.storage.sqlite_path) {
        Ok(persisted_removed) => {
            audit(
                &state,
                actor,
                "clear_shadow_routes",
                "learned_routes".to_string(),
                "updated",
                format!(
                    "memory_removed={}; persisted_removed={}",
                    memory_removed, persisted_removed
                ),
            );

            Json(json!(ok(json!({
                "memory_removed": memory_removed,
                "persisted_removed": persisted_removed
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn shadow_routes(State(state): State<AppState>) -> Json<Value> {
    let items = core::discover_shadow_apis_filtered(&state);
    Json(json!(ok(json!({
        "count": items.len(),
        "items": items
    }))))
}

pub async fn persisted_shadow_routes(State(state): State<AppState>) -> Json<Value> {
    match storage::query_learned_routes(&state.config.storage.sqlite_path) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn sync_shadow_routes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let actor = actor_from_headers(&headers);

    match core::sync_learned_routes_to_storage(&state, &state.config.storage.sqlite_path) {
        Ok(saved) => {
            audit(
                &state,
                actor,
                "sync_shadow_routes",
                "learned_routes".to_string(),
                "updated",
                format!("persisted_routes={saved}"),
            );

            Json(json!(ok(json!({
                "persisted_routes": saved
            }))))
        }
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn behavior_baselines(
    State(state): State<AppState>,
    Query(query): Query<BehaviorBaselineQuery>,
) -> Json<Value> {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let items = state.rate_limiter.snapshot_behavior(limit);

    Json(json!(ok(json!({
        "count": items.len(),
        "limit": limit,
        "items": items
    }))))
}

pub async fn recent_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchFilters>,
) -> Json<Value> {
    match storage::query_security_events(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn recent_audits(
    State(state): State<AppState>,
    Query(query): Query<crate::types::AuditSearchFilters>,
) -> Json<Value> {
    match storage::query_admin_audits(&state.config.storage.sqlite_path, &query) {
        Ok(items) => Json(json!(ok(json!({
            "count": items.len(),
            "limit": query.limit.unwrap_or(20),
            "offset": query.offset.unwrap_or(0),
            "items": items
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

pub async fn metrics(State(state): State<AppState>) -> Json<Value> {
    let telemetry_delivery = state.telemetry_delivery.snapshot();

    match storage::metrics_snapshot(&state.config.storage.sqlite_path) {
        Ok(metrics) => Json(json!(ok(json!({
            "public_bind_addr": state.config.server.public_bind_addr,
            "admin_bind_addr": state.config.server.admin_bind_addr,
            "active_temp_blocks": state.mitigation_store.active_block_count(),
            "reputation_entries": state.mitigation_store.list_reputations().len(),
            "persisted_active_mitigations": metrics.persisted_active_mitigations,
            "persisted_reputations": metrics.persisted_reputations,
            "persisted_learned_routes": metrics.persisted_learned_routes,
            "total_events": metrics.total_events,
            "blocked_events": metrics.blocked_events,
            "total_audits": metrics.total_audits,
            "latest_rule_ids": metrics.latest_rule_ids,
            "shadow_routes_discovered": core::discover_shadow_apis_filtered(&state).len(),
            "raw_shadow_routes_discovered": core::discover_shadow_apis_raw(&state).len(),
            "behavior_baseline_entries": state.rate_limiter.behavior_entry_count(),
            "persisted_behavior_snapshots": metrics.persisted_behavior_snapshots,
            "approved_shadow_routes": metrics.approved_shadow_routes,
            "promoted_spec_routes": metrics.promoted_spec_routes,
            "managed_spec_routes": metrics.managed_spec_routes,
            "analyst_suppressions": metrics.analyst_suppressions,
            "source_allowlist_entries": metrics.source_allowlist_entries,
            "principal_allowlist_entries": metrics.principal_allowlist_entries,
            "response_contracts": metrics.response_contracts,
            "policy_bundles": metrics.policy_bundles,
            "scoped_source_allowlist_entries": metrics.scoped_source_allowlist_entries,
            "scoped_principal_allowlist_entries": metrics.scoped_principal_allowlist_entries,
            "tri_scoped_allowlist_entries": metrics.tri_scoped_allowlist_entries,
            "restore_refusals": metrics.restore_refusals,
            "managed_spec_release_states": metrics.managed_spec_release_states,
            "restore_refusal_alerts": metrics.restore_refusal_alerts,
            "critical_restore_refusal_alerts": metrics.critical_restore_refusal_alerts,
            "control_plane_telemetry": {
                "enabled": state.config.control_plane.telemetry_enabled,
                "sent_total": telemetry_delivery.sent_total,
                "failed_total": telemetry_delivery.failed_total,
                "dropped_total": telemetry_delivery.dropped_total,
                "retried_total": telemetry_delivery.retried_total
            }
        })))),
        Err(e) => Json(json!(err::<Value>(e.to_string()))),
    }
}

fn actor_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-admin-actor")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")
        .to_string()
}

fn audit(
    state: &AppState,
    actor: String,
    action: &str,
    target: String,
    result: &str,
    details: String,
) {
    let audit = AdminAudit {
        timestamp: Utc::now(),
        actor,
        action: action.to_string(),
        target,
        result: result.to_string(),
        details,
    };

    if let Err(e) = storage::persist_admin_audit(&state.config.storage.sqlite_path, &audit) {
        tracing::error!(error = %e, "failed to persist admin audit");
    }
}
