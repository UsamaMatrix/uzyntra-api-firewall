use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::RwLock,
};

use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    config::{
        AppConfig, BodySchemaConfig, ConfiguredRouteSpec, RouteSensitivity, SchemaFieldKind,
        SpecUnknownRouteMode,
    },
    storage,
    types::{
        resolve_rule_mode, AppState, AttackClass, AuthStatus, EnrichedRequestContext, Finding,
        FindingEvidence, ParsedBodyField, PrincipalKey, RequestContext, SchemaValidationResult,
        Severity,
    },
};

static SEGMENT_ID_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([0-9]+|[0-9a-fA-F]{8,}|[A-Za-z0-9_-]{16,}|[0-9a-fA-F-]{36})$").unwrap()
});

static ROUTE_MEMORY: Lazy<RwLock<HashMap<String, crate::types::LearnedRoute>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone)]
pub struct CompiledRouteSpec {
    pub method: String,
    pub path_template: String,
    pub normalized_template: String,
    pub auth_required: bool,
    pub required_headers: Vec<String>,
    pub required_query: Vec<String>,
    pub required_scopes: Vec<String>,
    pub sensitivity: RouteSensitivity,
    pub body: BodySchemaConfig,
}

#[derive(Debug, Clone)]
pub struct CompiledSpecDb {
    pub routes: Vec<CompiledRouteSpec>,
    pub unknown_route_mode: SpecUnknownRouteMode,
}

pub async fn request_context_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let headers = parts.headers.clone();

    let source_ip = resolve_source_ip(&state, &headers, parts.extensions.get::<ConnectInfo<SocketAddr>>());
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(ToOwned::to_owned);
    let method = parts.method.to_string();

    let body_bytes = match to_bytes(body, state.config.proxy.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to read request body in request_context_middleware");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let preview_limit = state.config.security.max_inspection_body_bytes.min(body_bytes.len());
    let preview = String::from_utf8_lossy(&body_bytes[..preview_limit]).to_string();
    let body_preview = if preview.is_empty() { None } else { Some(preview.clone()) };

    let parsed_body_fields = extract_parsed_fields(&preview);
    let auth_status = resolve_auth_status(&state, &path, &headers);

    let request_id = headers
        .get(state.config.security.request_id_header.as_str())
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let context = RequestContext {
        request_id,
        timestamp: Utc::now(),
        source_ip,
        method,
        path,
        query,
        body_preview,
        parsed_body_fields,
        auth_status,
    };

    parts.extensions.insert(context.clone());

    let rebuilt = Request::from_parts(parts, Body::from(body_bytes));
    let mut response = next.run(rebuilt).await;

    if let Ok(value) = HeaderValue::from_str(&context.request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

pub async fn security_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let context = request.extensions().get::<RequestContext>().cloned();

    if let Some(ctx) = &context {
        if let Some(active) = state.mitigation_store.get_active_block(&ctx.source_ip) {
            warn!(
                request_id = %ctx.request_id,
                source_ip = %ctx.source_ip,
                expires_at = %active.expires_at,
                "blocked source attempted request"
            );

            let mut response = (StatusCode::FORBIDDEN, "source temporarily blocked").into_response();
            if let Ok(value) = HeaderValue::from_str(&ctx.request_id) {
                response.headers_mut().insert("x-request-id", value);
            }
            return response;
        }
    }

    next.run(request).await
}

pub async fn admin_auth_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if !state.config.auth.admin.enabled {
        return next.run(request).await;
    }

    let provided = request
        .headers()
        .get(state.config.auth.admin.header_name.as_str())
        .and_then(|v| v.to_str().ok());

    let expected = state.config.auth.admin.token.as_str();

    if provided != Some(expected) {
        return (StatusCode::UNAUTHORIZED, "missing or invalid admin token").into_response();
    }

    next.run(request).await
}

pub fn compiled_spec_db(config: &AppConfig) -> CompiledSpecDb {
    let routes = config.spec.routes.iter().map(compile_route).collect();

    CompiledSpecDb {
        routes,
        unknown_route_mode: config.spec.unknown_route_mode.clone(),
    }
}

fn compile_route(route: &ConfiguredRouteSpec) -> CompiledRouteSpec {
    CompiledRouteSpec {
        method: route.method.to_ascii_uppercase(),
        path_template: route.path_template.clone(),
        normalized_template: normalize_path_template(&route.path_template),
        auth_required: route.auth_required,
        required_headers: route
            .required_headers
            .iter()
            .map(|h| h.to_ascii_lowercase())
            .collect(),
        required_query: route.required_query.clone(),
        required_scopes: route.required_scopes.clone(),
        sensitivity: route.sensitivity.clone(),
        body: route.body.clone(),
    }
}

pub fn enrich_request(
    state: &AppState,
    request: &RequestContext,
    headers: &HeaderMap,
) -> EnrichedRequestContext {
    let canonical_path = canonical_security_path(&request.path);
    let normalized_path = normalize_runtime_path(&canonical_path);
    let principal = derive_principal(state, request, headers);
    let jwt_claims = parse_jwt_claims(headers);
    let tenant_id = jwt_claims
        .as_ref()
        .and_then(|m| m.get("tenant_id"))
        .and_then(as_string)
        .or_else(|| header_value(headers, "x-tenant-id"));
    let user_id = jwt_claims
        .as_ref()
        .and_then(|m| m.get("sub"))
        .and_then(as_string)
        .or_else(|| header_value(headers, "x-user-id"));
    let jwt_sub = jwt_claims
        .as_ref()
        .and_then(|m| m.get("sub"))
        .and_then(as_string);
    let api_key_hash = api_key_hash_from_headers(state, headers);

    let spec = compiled_spec_db(&state.config);
    let matched = spec_match(&spec, &request.method, &normalized_path);

    let (normalized_route, sensitivity, required_scopes) = if let Some(route) = matched {
        (
            route.path_template.clone(),
            route.sensitivity.clone(),
            route.required_scopes.clone(),
        )
    } else {
        (
            normalized_path.clone(),
            RouteSensitivity::AuthenticatedStandard,
            Vec::new(),
        )
    };

    let has_auth = matches!(request.auth_status, AuthStatus::Satisfied);
    remember_route(&request.method, &normalized_path, has_auth);

    EnrichedRequestContext {
        request: request.clone(),
        normalized_path,
        normalized_route,
        principal,
        tenant_id,
        user_id,
        jwt_sub,
        api_key_hash,
        sensitivity,
        required_scopes,
        schema_mode: state.config.spec.unknown_route_mode.clone(),
        object_id_candidates: extract_object_id_candidates(request),
    }
}

pub fn validate_against_spec(
    state: &AppState,
    enriched: &EnrichedRequestContext,
    headers: &HeaderMap,
) -> SchemaValidationResult {
    if !state.config.spec.enabled {
        return SchemaValidationResult {
            allow: true,
            finding: None,
            matched_route: None,
        };
    }

    let spec = compiled_spec_db(&state.config);
    let Some(route) = spec_match(&spec, &enriched.request.method, &enriched.normalized_path) else {
        return unknown_route_result(state, enriched, spec.unknown_route_mode);
    };

    for required in &route.required_headers {
        if header_value(headers, required).is_none() {
            return schema_block(
                state,
                enriched,
                "schema.missing_required_header",
                Severity::High,
                format!("missing required header '{required}'"),
                format!("header:{required}"),
                required.clone(),
            );
        }
    }

    let query_map = parse_query_map(enriched.request.query.as_deref());
    for required in &route.required_query {
        if !query_map.contains_key(required) {
            return schema_block(
                state,
                enriched,
                "schema.missing_required_query",
                Severity::Medium,
                format!("missing required query parameter '{required}'"),
                format!("query:{required}"),
                required.clone(),
            );
        }
    }

    if route.auth_required && !has_auth_context(state, headers) {
        return schema_block(
            state,
            enriched,
            "schema.auth_required",
            Severity::High,
            "authentication required for matched route".to_string(),
            "request.auth".to_string(),
            enriched.request.path.clone(),
        );
    }

    if !route.body.required_fields.is_empty() || route.body.require_json {
        let Some(body) = enriched.request.body_preview.as_deref() else {
            return schema_block(
                state,
                enriched,
                "schema.body_required",
                Severity::High,
                "JSON body required by schema".to_string(),
                "request.body".to_string(),
                String::new(),
            );
        };

        let parsed: Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => {
                return schema_block(
                    state,
                    enriched,
                    "schema.invalid_json",
                    Severity::High,
                    "invalid JSON body for schema-protected route".to_string(),
                    "request.body".to_string(),
                    truncate(body, 160),
                )
            }
        };

        if route.body.max_depth > 0 && json_depth(&parsed) > route.body.max_depth {
            return schema_block(
                state,
                enriched,
                "schema.max_depth",
                Severity::Medium,
                format!("JSON body exceeds max depth {}", route.body.max_depth),
                "request.body".to_string(),
                truncate(body, 160),
            );
        }

        if route.body.max_fields > 0 && json_field_count(&parsed) > route.body.max_fields {
            return schema_block(
                state,
                enriched,
                "schema.max_fields",
                Severity::Medium,
                format!("JSON body exceeds max field count {}", route.body.max_fields),
                "request.body".to_string(),
                truncate(body, 160),
            );
        }

        for field in &route.body.required_fields {
            let Some(value) = parsed.get(&field.name) else {
                if field.required {
                    return schema_block(
                        state,
                        enriched,
                        "schema.required_field_missing",
                        Severity::High,
                        format!("required body field '{}' missing", field.name),
                        format!("body.{}", field.name),
                        String::new(),
                    );
                }
                continue;
            };

            if !matches_kind(value, &field.kind) {
                return schema_block(
                    state,
                    enriched,
                    "schema.field_type_mismatch",
                    Severity::High,
                    format!("body field '{}' does not match expected type", field.name),
                    format!("body.{}", field.name),
                    truncate(&value.to_string(), 160),
                );
            }
        }
    }

    SchemaValidationResult {
        allow: true,
        finding: None,
        matched_route: Some(route.path_template.clone()),
    }
}

pub fn calculate_risk(findings: &[Finding], reputation_score: i32) -> f32 {
    let mut schema_violation = 0.0;
    let mut behavior_anomaly = 0.0;
    let mut token_risk = 0.0;
    let mut object_abuse = 0.0;
    let reputation = reputation_score.max(0) as f32;

    for finding in findings {
        match finding.attack_class {
            AttackClass::SchemaViolation => schema_violation += severity_weight(&finding.severity),
            AttackClass::JwtAbuse | AttackClass::BrokenAuthentication => {
                token_risk += severity_weight(&finding.severity)
            }
            AttackClass::ObjectEnumeration | AttackClass::TenantBoundaryViolation => {
                object_abuse += severity_weight(&finding.severity)
            }
            AttackClass::BehaviorAnomaly | AttackClass::BruteForce | AttackClass::RateLimitExceeded => {
                behavior_anomaly += severity_weight(&finding.severity)
            }
            _ => {}
        }
    }

    schema_violation * 2.0
        + behavior_anomaly * 2.5
        + object_abuse * 2.5
        + token_risk * 2.0
        + reputation * 1.5
}

pub fn clear_learned_routes() -> usize {
    let mut guard = ROUTE_MEMORY.write().expect("route memory poisoned");
    let count = guard.len();
    guard.clear();
    count
}

pub fn shadow_routes_snapshot(state: &AppState) -> Vec<crate::types::LearnedRoute> {
    discover_shadow_apis(state)
}

pub fn learned_routes_snapshot() -> Vec<crate::types::LearnedRoute> {
    let guard = ROUTE_MEMORY.read().expect("route memory poisoned");
    let mut items: Vec<_> = guard.values().cloned().collect();
    items.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    items
}

pub fn restore_learned_routes(routes: &[crate::types::LearnedRoute]) {
    let mut guard = ROUTE_MEMORY.write().expect("route memory poisoned");

    for route in routes {
        let key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
        match guard.get_mut(&key) {
            Some(existing) => {
                existing.first_seen = existing.first_seen.min(route.first_seen);
                existing.last_seen = existing.last_seen.max(route.last_seen);
                existing.hits = existing.hits.max(route.hits);
                existing.has_auth = existing.has_auth || route.has_auth;
            }
            None => {
                guard.insert(key, route.clone());
            }
        }
    }
}

pub fn approved_shadow_route_keys(sqlite_path: &str) -> anyhow::Result<std::collections::HashSet<String>> {
    let items = storage::query_approved_shadow_routes(sqlite_path)?;
    Ok(items
        .into_iter()
        .map(|r| format!("{}:{}", r.method.to_ascii_uppercase(), r.normalized_path))
        .collect())
}

pub fn promoted_spec_route_keys(
    sqlite_path: &str,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let items = storage::query_promoted_spec_routes(sqlite_path)?;
    Ok(items
        .into_iter()
        .map(|r| format!("{}:{}", r.method.to_ascii_uppercase(), r.normalized_path))
        .collect())
}

pub fn discover_shadow_apis_raw(state: &AppState) -> Vec<crate::types::LearnedRoute> {
    discover_shadow_apis(state)
}

pub fn managed_spec_route_keys(
    sqlite_path: &str,
) -> anyhow::Result<std::collections::HashSet<String>> {
    let items = storage::query_managed_spec_routes(sqlite_path)?;
    Ok(items
        .into_iter()
        .map(|r| format!("{}:{}", r.method.to_ascii_uppercase(), r.normalized_path))
        .collect())
}

pub fn discover_shadow_apis_filtered(state: &AppState) -> Vec<crate::types::LearnedRoute> {
    let approved = approved_shadow_route_keys(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let promoted = promoted_spec_route_keys(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let managed = managed_spec_route_keys(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    discover_shadow_apis(state)
        .into_iter()
        .filter(|route| {
            let key = format!("{}:{}", route.method.to_ascii_uppercase(), route.normalized_path);
            !approved.contains(&key) && !promoted.contains(&key) && !managed.contains(&key)
        })
        .collect()
}

pub fn is_tri_scoped_allowlisted(
    state: &AppState,
    source_ip: &str,
    principal_key: &str,
    path: &str,
) -> bool {
    match storage::query_tri_scoped_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => items.iter().any(|entry| {
            entry.source_ip == source_ip
                && principal_key.starts_with(&entry.principal_prefix)
                && path.starts_with(&entry.path_prefix)
        }),
        Err(_) => false,
    }
}

pub fn export_gateway_managed_spec_inventory(
    state: &AppState,
) -> crate::types::GatewayManagedSpecExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| {
            let contract = contracts.iter().find(|contract| {
                contract.method.eq_ignore_ascii_case(&route.method)
                    && contract.normalized_path == route.normalized_path
            });

            crate::types::GatewayRoutePolicyExport {
                method: route.method,
                path: route.normalized_path,
                auth_required: route.auth_required,
                expected_status: contract.map(|c| c.expected_status),
                expected_content_type_prefix: contract
                    .map(|c| c.expected_content_type_prefix.clone()),
                required_headers: contract
                    .map(|c| c.required_headers.clone())
                    .unwrap_or_default(),
            }
        })
        .collect();

    crate::types::GatewayManagedSpecExport {
        exported_at: chrono::Utc::now(),
        schema_version: "gateway-v1".to_string(),
        routes,
    }
}

pub fn build_response_contract_from_mismatch_event(
    event: &crate::types::SecurityEvent,
    actor: String,
    note: Option<String>,
) -> Option<crate::types::ResponseContract> {
    let mismatch = event.findings.iter().find(|f| f.rule_id == "response.contract_mismatch")?;

    let method = event.method.to_ascii_uppercase();
    let normalized_path = normalize_runtime_path(&canonical_security_path(&event.path));

    let mut expected_status: Option<u16> = None;
    let mut expected_content_type_prefix: Option<String> = None;
    let mut required_headers: Vec<String> = Vec::new();

    for evidence in &mismatch.evidence {
        if evidence.location == "response.contract.status" {
            if let Some(raw) = evidence.value_preview.split(',').next() {
                if let Some(value) = raw.trim().strip_prefix("expected=") {
                    expected_status = value.parse::<u16>().ok();
                }
            }
        } else if evidence.location == "response.contract.content_type" {
            if let Some(raw) = evidence.value_preview.split(',').next() {
                if let Some(value) = raw.trim().strip_prefix("expected_prefix=") {
                    expected_content_type_prefix = Some(value.to_string());
                }
            }
        } else if evidence.location == "response.contract.missing_headers" {
            if !evidence.value_preview.trim().is_empty() {
                required_headers = evidence
                    .value_preview
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }

    Some(crate::types::ResponseContract {
        method,
        normalized_path,
        expected_status: expected_status?,
        expected_content_type_prefix: expected_content_type_prefix?,
        required_headers,
        approved_at: chrono::Utc::now(),
        approved_by: actor,
        note,
    })
}

pub fn restore_refusal_severity_for_count(count: usize) -> String {
    if count >= 3 {
        "critical".to_string()
    } else {
        "high".to_string()
    }
}

pub fn evaluate_release_guard(
    state: &AppState,
    method: &str,
    normalized_path: &str,
    target_channel: &str,
) -> crate::types::ReleaseGuardResult {
    let mut reasons = Vec::new();

    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let release_states = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let has_contract = contracts.iter().any(|c| {
        c.method.eq_ignore_ascii_case(method) && c.normalized_path == normalized_path
    });
    let current_channel = release_states.iter().find(|s| {
        s.method.eq_ignore_ascii_case(method) && s.normalized_path == normalized_path
    }).map(|s| s.channel.as_str());

    if target_channel == "exported" {
        if !has_contract {
            reasons.push("response contract required before exported".to_string());
        }
        if current_channel != Some("approved") {
            reasons.push("route must be in approved before exported".to_string());
        }
    }

    crate::types::ReleaseGuardResult {
        method: method.to_ascii_uppercase(),
        normalized_path: normalized_path.to_string(),
        allowed: reasons.is_empty(),
        reasons,
    }
}

pub fn export_kong_inventory(state: &AppState) -> crate::types::KongRouteExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let release_states = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let services = managed_routes
        .into_iter()
        .map(|route| {
            let contract = contracts.iter().find(|c| {
                c.method.eq_ignore_ascii_case(&route.method)
                    && c.normalized_path == route.normalized_path
            });
            let release_channel = release_states.iter().find(|s| {
                s.method.eq_ignore_ascii_case(&route.method)
                    && s.normalized_path == route.normalized_path
            }).map(|s| s.channel.clone());

            crate::types::KongServiceExport {
                name: format!(
                    "{}-{}",
                    route.method.to_ascii_lowercase(),
                    route.normalized_path.replace('/', "-").replace('{', "").replace('}', "")
                ),
                method: route.method,
                path: route.normalized_path,
                auth_required: route.auth_required,
                required_headers: contract.map(|c| c.required_headers.clone()).unwrap_or_default(),
                release_channel,
            }
        })
        .collect();

    crate::types::KongRouteExport {
        exported_at: chrono::Utc::now(),
        schema_version: "kong-v1".to_string(),
        services,
    }
}

pub fn export_envoy_inventory(state: &AppState) -> crate::types::EnvoyRouteExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let release_states = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| {
            let release_channel = release_states.iter().find(|s| {
                s.method.eq_ignore_ascii_case(&route.method)
                    && s.normalized_path == route.normalized_path
            }).map(|s| s.channel.clone());

            crate::types::EnvoyRouteRecord {
                match_path: route.normalized_path,
                method: route.method,
                auth_required: route.auth_required,
                release_channel,
            }
        })
        .collect();

    crate::types::EnvoyRouteExport {
        exported_at: chrono::Utc::now(),
        schema_version: "envoy-v1".to_string(),
        routes,
    }
}

pub fn build_contract_recommendations(state: &AppState) -> crate::types::ContractRecommendationSet {
    use std::collections::HashMap;

    let events = storage::recent_response_contract_mismatch_events(
        &state.config.storage.sqlite_path,
        200,
    ).unwrap_or_default();

    let mut grouped: HashMap<(String, String), Vec<crate::types::SecurityEvent>> = HashMap::new();
    for event in events {
        let method = event.method.to_ascii_uppercase();
        let normalized_path = normalize_runtime_path(&canonical_security_path(&event.path));
        grouped.entry((method, normalized_path)).or_default().push(event);
    }

    let mut items = Vec::new();
    for ((method, normalized_path), group) in grouped {
        let mut status_counts: HashMap<u16, usize> = HashMap::new();
        let mut content_type_counts: HashMap<String, usize> = HashMap::new();
        let mut header_counts: HashMap<String, usize> = HashMap::new();

        for event in &group {
            if let Some(finding) = event.findings.iter().find(|f| f.rule_id == "response.contract_mismatch") {
                for evidence in &finding.evidence {
                    if evidence.location == "response.contract.status" {
                        if let Some(raw) = evidence.value_preview.split(',').next() {
                            if let Some(value) = raw.trim().strip_prefix("expected=") {
                                if let Ok(status) = value.parse::<u16>() {
                                    *status_counts.entry(status).or_insert(0) += 1;
                                }
                            }
                        }
                    } else if evidence.location == "response.contract.content_type" {
                        if let Some(raw) = evidence.value_preview.split(',').next() {
                            if let Some(value) = raw.trim().strip_prefix("expected_prefix=") {
                                *content_type_counts.entry(value.to_string()).or_insert(0) += 1;
                            }
                        }
                    } else if evidence.location == "response.contract.missing_headers" {
                        for header in evidence.value_preview.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                            *header_counts.entry(header.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        let recommended_status = status_counts
            .into_iter().max_by_key(|(_, c)| *c).map(|(s, _)| s).unwrap_or(200);
        let recommended_content_type_prefix = content_type_counts
            .into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v)
            .unwrap_or_else(|| "application/json".to_string());
        let recommended_required_headers = header_counts
            .into_iter().filter(|(_, c)| *c >= 1).map(|(h, _)| h).collect();

        items.push(crate::types::ContractRecommendation {
            method,
            normalized_path,
            recommended_status,
            recommended_content_type_prefix,
            recommended_required_headers,
            supporting_events: group.len(),
        });
    }

    crate::types::ContractRecommendationSet {
        generated_at: chrono::Utc::now(),
        items,
    }
}

pub fn make_restore_refusal_alert(
    actor: String,
    bundle_id: String,
    reason: String,
    stored_digest_sha256: String,
    recomputed_digest_sha256: String,
) -> crate::types::RestoreRefusalAlert {
    crate::types::RestoreRefusalAlert {
        alert_id: format!("alert-{}", uuid::Uuid::new_v4()),
        created_at: chrono::Utc::now(),
        bundle_id,
        severity: "high".to_string(),
        status: "open".to_string(),
        reason,
        stored_digest_sha256,
        recomputed_digest_sha256,
        latest_actor: actor,
    }
}

pub fn is_valid_release_transition(current: Option<&str>, target: &str) -> bool {
    match (current, target) {
        (None, "draft") => true,
        (Some("draft"), "approved") => true,
        (Some("approved"), "exported") => true,
        (Some(c), t) if c == t => true,
        _ => false,
    }
}

pub fn export_api_gateway_policy_inventory(
    state: &AppState,
) -> crate::types::ApiGatewayPolicyExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let release_states = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| {
            let contract = contracts.iter().find(|c| {
                c.method.eq_ignore_ascii_case(&route.method)
                    && c.normalized_path == route.normalized_path
            });
            let release_channel = release_states.iter().find(|s| {
                s.method.eq_ignore_ascii_case(&route.method)
                    && s.normalized_path == route.normalized_path
            }).map(|s| s.channel.clone());

            crate::types::ApiGatewayPolicyRoute {
                method: route.method,
                path: route.normalized_path,
                auth_required: route.auth_required,
                required_headers: contract.map(|c| c.required_headers.clone()).unwrap_or_default(),
                release_channel,
            }
        })
        .collect();

    crate::types::ApiGatewayPolicyExport {
        exported_at: chrono::Utc::now(),
        schema_version: "api-gateway-policy-v1".to_string(),
        routes,
    }
}

pub fn export_manifest(state: &AppState) -> crate::types::ExportManifest {
    crate::types::ExportManifest {
        exported_at: chrono::Utc::now(),
        managed_routes: storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
            .unwrap_or_default().len(),
        response_contracts: storage::query_response_contracts(&state.config.storage.sqlite_path)
            .unwrap_or_default().len(),
        release_state_records: storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
            .unwrap_or_default().len(),
        policy_bundles: storage::query_policy_bundles(&state.config.storage.sqlite_path)
            .unwrap_or_default().len(),
    }
}

pub fn export_gateway_routing_only_inventory(
    state: &AppState,
) -> crate::types::GatewayRoutingOnlyExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| crate::types::GatewayRoutingOnlyRoute {
            method: route.method,
            path: route.normalized_path,
            auth_required: route.auth_required,
        })
        .collect();

    crate::types::GatewayRoutingOnlyExport {
        exported_at: chrono::Utc::now(),
        schema_version: "gateway-routing-only-v1".to_string(),
        routes,
    }
}

pub fn export_gateway_enforcement_inventory(
    state: &AppState,
) -> crate::types::GatewayEnforcementExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let release_states = storage::query_managed_spec_release_state(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| {
            let contract = contracts.iter().find(|c| {
                c.method.eq_ignore_ascii_case(&route.method)
                    && c.normalized_path == route.normalized_path
            });
            let release_channel = release_states.iter().find(|s| {
                s.method.eq_ignore_ascii_case(&route.method)
                    && s.normalized_path == route.normalized_path
            }).map(|s| s.channel.clone());

            crate::types::GatewayEnforcementRoute {
                method: route.method,
                path: route.normalized_path,
                auth_required: route.auth_required,
                expected_status: contract.map(|c| c.expected_status),
                expected_content_type_prefix: contract.map(|c| c.expected_content_type_prefix.clone()),
                required_headers: contract.map(|c| c.required_headers.clone()).unwrap_or_default(),
                release_channel,
            }
        })
        .collect();

    crate::types::GatewayEnforcementExport {
        exported_at: chrono::Utc::now(),
        schema_version: "gateway-enforcement-v1".to_string(),
        routes,
    }
}

pub fn record_restore_refusal(
    state: &AppState,
    actor: String,
    bundle_id: String,
    reason: String,
    stored_digest_sha256: String,
    recomputed_digest_sha256: String,
) {
    let refusal = crate::types::RestoreRefusalEvent {
        timestamp: chrono::Utc::now(),
        actor,
        bundle_id,
        reason,
        stored_digest_sha256,
        recomputed_digest_sha256,
    };
    let _ = storage::persist_restore_refusal(&state.config.storage.sqlite_path, &refusal);
}

pub fn export_enforcement_managed_spec_inventory(
    state: &AppState,
) -> crate::types::EnforcementManagedSpecExport {
    let managed_routes = storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
        .unwrap_or_default();
    let contracts = storage::query_response_contracts(&state.config.storage.sqlite_path)
        .unwrap_or_default();

    let routes = managed_routes
        .into_iter()
        .map(|route| {
            let expected_response = contracts.iter().find(|contract| {
                contract.method.eq_ignore_ascii_case(&route.method)
                    && contract.normalized_path == route.normalized_path
            }).map(|contract| crate::types::EnforcementResponseContract {
                expected_status: contract.expected_status,
                expected_content_type_prefix: contract.expected_content_type_prefix.clone(),
                required_headers: contract.required_headers.clone(),
            });

            crate::types::EnforcementManagedRoute {
                method: route.method,
                normalized_path: route.normalized_path,
                auth_required: route.auth_required,
                expected_response,
            }
        })
        .collect();

    crate::types::EnforcementManagedSpecExport {
        exported_at: chrono::Utc::now(),
        version: "v1".to_string(),
        routes,
    }
}

pub fn build_response_contract_from_request(
    actor: String,
    req: crate::types::ApproveContractMismatchRequest,
) -> crate::types::ResponseContract {
    crate::types::ResponseContract {
        method: req.method.to_ascii_uppercase(),
        normalized_path: req.normalized_path,
        expected_status: req.expected_status,
        expected_content_type_prefix: req.expected_content_type_prefix,
        required_headers: req.required_headers,
        approved_at: chrono::Utc::now(),
        approved_by: actor,
        note: req.note,
    }
}

pub fn compute_live_policy_digest(export: &crate::types::LivePolicyExport) -> String {
    use sha2::{Digest, Sha256};

    let canonical = json!({
        "global_rule_modes": canonical_rule_modes(&export.global_rule_modes),
        "route_overrides": canonical_route_overrides(&export.route_overrides),
        "route_rate_limits": canonical_route_rate_limits(&export.route_rate_limits),
        "route_behavior_overrides": canonical_route_behavior_overrides(&export.route_behavior_overrides),
    });

    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn canonical_rule_modes(
    map: &std::collections::HashMap<String, crate::config::RuleMode>,
) -> Vec<(String, crate::config::RuleMode)> {
    let mut items: Vec<_> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));
    items
}

fn canonical_route_overrides(items: &[crate::config::RoutePolicyOverride]) -> Vec<Value> {
    let mut rows: Vec<Value> = items
        .iter()
        .map(|item| {
            let mut rule_modes: Vec<_> = item
                .rule_modes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            rule_modes.sort_by(|a, b| a.0.cmp(&b.0));
            json!({ "path_prefix": item.path_prefix, "rule_modes": rule_modes })
        })
        .collect();
    rows.sort_by(|a, b| {
        let a_p = a.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        let b_p = b.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        a_p.cmp(b_p)
    });
    rows
}

fn canonical_route_rate_limits(items: &[crate::config::RouteRateLimitOverride]) -> Vec<Value> {
    let mut rows: Vec<Value> = items
        .iter()
        .map(|item| json!({
            "path_prefix": item.path_prefix,
            "requests_per_window": item.requests_per_window,
            "window_secs": item.window_secs,
        }))
        .collect();
    rows.sort_by(|a, b| {
        let a_p = a.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        let b_p = b.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        a_p.cmp(b_p)
    });
    rows
}

fn canonical_route_behavior_overrides(items: &[crate::config::RouteBehaviorOverride]) -> Vec<Value> {
    let mut rows: Vec<Value> = items
        .iter()
        .map(|item| json!({
            "path_prefix": item.path_prefix,
            "warmup_min_samples": item.warmup_min_samples,
            "object_enumeration_threshold": item.object_enumeration_threshold,
            "object_window_secs": item.object_window_secs,
        }))
        .collect();
    rows.sort_by(|a, b| {
        let a_p = a.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        let b_p = b.get("path_prefix").and_then(|v| v.as_str()).unwrap_or_default();
        a_p.cmp(b_p)
    });
    rows
}

pub fn verify_policy_bundle(
    bundle: &crate::types::PolicyBundle,
    live_policy: &crate::types::LivePolicyExport,
) -> crate::types::PolicyBundleVerificationResult {
    let stored_digest_sha256 = bundle.digest_sha256.clone();
    let recomputed_digest_sha256 = compute_live_policy_digest(&bundle.live_policy);
    let live_policy_digest_sha256 = compute_live_policy_digest(live_policy);
    let digest_match = stored_digest_sha256 == recomputed_digest_sha256;
    let matches_live_policy = recomputed_digest_sha256 == live_policy_digest_sha256;

    crate::types::PolicyBundleVerificationResult {
        bundle_id: bundle.bundle_id.clone(),
        verified_at: chrono::Utc::now(),
        stored_digest_sha256,
        recomputed_digest_sha256,
        digest_match,
        live_policy_digest_sha256,
        matches_live_policy,
    }
}

pub fn is_source_allowlisted_for_path(state: &AppState, source_ip: &str, path: &str) -> bool {
    match storage::query_scoped_source_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => items.iter().any(|entry| {
            entry.source_ip == source_ip && path.starts_with(&entry.path_prefix)
        }),
        Err(_) => false,
    }
}

pub fn is_principal_allowlisted_for_path(
    state: &AppState,
    principal_key: &str,
    path: &str,
) -> bool {
    match storage::query_scoped_principal_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => items.iter().any(|entry| {
            principal_key.starts_with(&entry.principal_prefix)
                && path.starts_with(&entry.path_prefix)
        }),
        Err(_) => false,
    }
}

pub fn export_managed_spec_inventory(state: &AppState) -> crate::types::ManagedSpecExport {
    crate::types::ManagedSpecExport {
        exported_at: chrono::Utc::now(),
        managed_spec_routes: storage::query_managed_spec_routes(&state.config.storage.sqlite_path)
            .unwrap_or_default(),
        response_contracts: storage::query_response_contracts(&state.config.storage.sqlite_path)
            .unwrap_or_default(),
    }
}

pub fn is_source_allowlisted(state: &AppState, source_ip: &str) -> bool {
    match storage::query_source_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => items.iter().any(|entry| entry.source_ip == source_ip),
        Err(_) => false,
    }
}

pub fn is_principal_allowlisted(state: &AppState, principal_key: &str) -> bool {
    match storage::query_principal_allowlist(&state.config.storage.sqlite_path) {
        Ok(items) => items.iter().any(|entry| principal_key.starts_with(&entry.principal_prefix)),
        Err(_) => false,
    }
}

pub fn make_policy_bundle_id() -> String {
    format!("bundle-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"))
}

pub fn compute_policy_diff(
    live: &crate::types::LivePolicyExport,
    saved: &crate::types::LivePolicyExport,
    bundle_id: Option<String>,
) -> crate::types::PolicyDiffResult {
    crate::types::PolicyDiffResult {
        compared_at: chrono::Utc::now(),
        bundle_id,
        has_changes: live.global_rule_modes != saved.global_rule_modes
            || live.route_overrides != saved.route_overrides
            || live.route_rate_limits != saved.route_rate_limits
            || live.route_behavior_overrides != saved.route_behavior_overrides,
        global_rule_modes_changed: live.global_rule_modes != saved.global_rule_modes,
        route_overrides_changed: live.route_overrides != saved.route_overrides,
        route_rate_limits_changed: live.route_rate_limits != saved.route_rate_limits,
        route_behavior_overrides_changed: live.route_behavior_overrides != saved.route_behavior_overrides,
    }
}

pub fn response_contract_for_route(
    state: &AppState,
    method: &str,
    normalized_path: &str,
) -> Option<crate::types::ResponseContract> {
    match storage::query_response_contracts(&state.config.storage.sqlite_path) {
        Ok(items) => items.into_iter().find(|item| {
            item.method.eq_ignore_ascii_case(method)
                && item.normalized_path == normalized_path
        }),
        Err(_) => None,
    }
}

pub fn export_live_policy_state(state: &AppState) -> crate::types::LivePolicyExport {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    crate::types::LivePolicyExport {
        exported_at: chrono::Utc::now(),
        global_rule_modes: guard.global_rule_modes.clone(),
        route_overrides: guard.route_overrides.clone(),
        route_rate_limits: guard.route_rate_limits.clone(),
        route_behavior_overrides: guard.route_behavior_overrides.clone(),
    }
}

pub fn filter_suppressed_findings(
    state: &AppState,
    path: &str,
    findings: Vec<crate::types::Finding>,
) -> Vec<crate::types::Finding> {
    let suppressions = match storage::query_analyst_suppressions(&state.config.storage.sqlite_path) {
        Ok(items) => items,
        Err(_) => return findings,
    };

    findings
        .into_iter()
        .filter(|finding| {
            !suppressions.iter().any(|suppression| {
                if suppression.rule_id != finding.rule_id {
                    return false;
                }

                match &suppression.path_prefix {
                    Some(prefix) => path.starts_with(prefix.as_str()),
                    None => true,
                }
            })
        })
        .collect()
}

pub fn sync_learned_routes_to_storage(
    state: &AppState,
    sqlite_path: &str,
) -> anyhow::Result<usize> {
    let items = discover_shadow_apis_filtered(state);
    storage::replace_learned_routes(sqlite_path, &items)?;
    Ok(items.len())
}

pub fn discover_shadow_apis(state: &AppState) -> Vec<crate::types::LearnedRoute> {
    if !state.config.discovery.enabled {
        return Vec::new();
    }

    let spec = compiled_spec_db(&state.config);
    let guard = ROUTE_MEMORY.read().expect("route memory poisoned");
    guard
        .values()
        .filter(|route| {
            route.hits >= state.config.discovery.shadow_min_hits
                && spec_match(&spec, &route.method, &route.normalized_path).is_none()
        })
        .cloned()
        .collect()
}

pub fn derive_principal(
    state: &AppState,
    request: &RequestContext,
    headers: &HeaderMap,
) -> PrincipalKey {
    if let Some(claims) = parse_jwt_claims(headers) {
        let tenant = claims.get("tenant_id").and_then(as_string);
        let sub = claims.get("sub").and_then(as_string);
        if let (Some(tenant), Some(sub)) = (tenant.clone(), sub.clone()) {
            return PrincipalKey::TenantUser(tenant, sub);
        }
        if let Some(sub) = sub {
            return PrincipalKey::JwtSub(sub);
        }
    }

    if let Some(hash) = api_key_hash_from_headers(state, headers) {
        return PrincipalKey::ApiKeyHash(hash);
    }

    PrincipalKey::Ip(request.source_ip.to_string())
}

pub fn normalize_runtime_path(path: &str) -> String {
    let mut out = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() {
            continue;
        }
        if SEGMENT_ID_RE.is_match(seg) {
            out.push("{id}".to_string());
        } else {
            out.push(seg.to_ascii_lowercase());
        }
    }
    format!("/{}", out.join("/"))
}

pub fn canonical_security_path(path: &str) -> String {
    if path == "/proxy" {
        "/".to_string()
    } else if let Some(stripped) = path.strip_prefix("/proxy/") {
        format!("/{}", stripped)
    } else {
        path.to_string()
    }
}

fn normalize_path_template(path: &str) -> String {
    normalize_runtime_path(path)
}

fn spec_match<'a>(
    spec: &'a CompiledSpecDb,
    method: &str,
    normalized_path: &str,
) -> Option<&'a CompiledRouteSpec> {
    spec.routes.iter().find(|route| {
        route.method.eq_ignore_ascii_case(method)
            && route_pattern_match(&route.normalized_template, normalized_path)
    })
}

fn route_pattern_match(template: &str, path: &str) -> bool {
    let lhs: Vec<_> = template.trim_matches('/').split('/').collect();
    let rhs: Vec<_> = path.trim_matches('/').split('/').collect();

    if lhs.len() != rhs.len() {
        return false;
    }

    lhs.iter().zip(rhs.iter()).all(|(a, b)| {
        (a.starts_with('{') && a.ends_with('}')) || a.eq_ignore_ascii_case(b)
    })
}

fn unknown_route_result(
    state: &AppState,
    enriched: &EnrichedRequestContext,
    mode: SpecUnknownRouteMode,
) -> SchemaValidationResult {
    let severity = match mode {
        SpecUnknownRouteMode::Allow => Severity::Low,
        SpecUnknownRouteMode::Detect => Severity::Medium,
        SpecUnknownRouteMode::Block => Severity::High,
    };

    let finding = Finding {
        rule_id: "schema.unknown_route".to_string(),
        attack_class: AttackClass::SchemaViolation,
        severity,
        confidence: 0.93,
        message: format!("route not present in configured API spec: {}", enriched.normalized_path),
        evidence: vec![FindingEvidence {
            location: "request.path".to_string(),
            value_preview: enriched.normalized_path.clone(),
        }],
        mode: resolve_rule_mode(state, &enriched.request.path, "schema.unknown_route"),
    };

    SchemaValidationResult {
        allow: !matches!(mode, SpecUnknownRouteMode::Block),
        finding: Some(finding),
        matched_route: None,
    }
}

fn schema_block(
    state: &AppState,
    enriched: &EnrichedRequestContext,
    rule_id: &str,
    severity: Severity,
    message: String,
    location: String,
    value_preview: String,
) -> SchemaValidationResult {
    SchemaValidationResult {
        allow: false,
        finding: Some(Finding {
            rule_id: rule_id.to_string(),
            attack_class: AttackClass::SchemaViolation,
            severity,
            confidence: 0.97,
            message,
            evidence: vec![FindingEvidence {
                location,
                value_preview,
            }],
            mode: resolve_rule_mode(state, &enriched.request.path, rule_id),
        }),
        matched_route: None,
    }
}

fn severity_weight(severity: &Severity) -> f32 {
    match severity {
        Severity::Low => 1.0,
        Severity::Medium => 2.0,
        Severity::High => 3.5,
        Severity::Critical => 5.0,
    }
}

fn remember_route(method: &str, normalized_path: &str, has_auth: bool) {
    let now = Utc::now();
    let key = format!("{}:{}", method.to_ascii_uppercase(), normalized_path);
    let mut guard = ROUTE_MEMORY.write().expect("route memory poisoned");
    match guard.get_mut(&key) {
        Some(route) => {
            route.last_seen = now;
            route.hits += 1;
            route.has_auth = route.has_auth || has_auth;
        }
        None => {
            guard.insert(
                key,
                crate::types::LearnedRoute {
                    method: method.to_ascii_uppercase(),
                    normalized_path: normalized_path.to_string(),
                    first_seen: now,
                    last_seen: now,
                    hits: 1,
                    has_auth,
                },
            );
        }
    }
}

fn extract_object_id_candidates(request: &RequestContext) -> Vec<String> {
    let mut out = Vec::new();

    for seg in request.path.split('/') {
        if SEGMENT_ID_RE.is_match(seg) {
            out.push(seg.to_string());
        }
    }

    if let Some(query) = &request.query {
        for (k, v) in parse_query_map(Some(query)) {
            if k.ends_with("id") || k.ends_with("_id") {
                out.push(v);
            }
        }
    }

    for field in &request.parsed_body_fields {
        let lower = field.key.to_ascii_lowercase();
        if lower.ends_with("id") || lower.ends_with("_id") {
            out.push(field.value_preview.clone());
        }
    }

    out
}

fn resolve_source_ip(
    state: &AppState,
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
) -> IpAddr {
    if state.config.server.trust_x_forwarded_for {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    connect_info
        .map(|c| c.0.ip())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap())
}

fn resolve_auth_status(state: &AppState, path: &str, headers: &HeaderMap) -> AuthStatus {
    if !state.config.auth.enabled {
        return AuthStatus::NotRequired;
    }

    let protected = state
        .config
        .auth
        .protected_path_prefixes
        .iter()
        .any(|prefix| path.starts_with(prefix));

    if !protected {
        return AuthStatus::NotRequired;
    }

    let Some(value) = headers
        .get(state.config.auth.header_name.as_str())
        .and_then(|v| v.to_str().ok())
    else {
        return AuthStatus::Missing;
    };

    if state.config.auth.api_keys.iter().any(|k| k == value) {
        AuthStatus::Satisfied
    } else {
        AuthStatus::Invalid
    }
}

fn has_auth_context(state: &AppState, headers: &HeaderMap) -> bool {
    let valid_api_key = headers
        .get(state.config.auth.header_name.as_str())
        .and_then(|v| v.to_str().ok())
        .map(|value| state.config.auth.api_keys.iter().any(|k| k == value))
        .unwrap_or(false);

    let valid_jwt_context = parse_jwt_claims(headers).is_some();

    valid_api_key || valid_jwt_context
}

fn extract_parsed_fields(body_preview: &str) -> Vec<ParsedBodyField> {
    let Ok(value) = serde_json::from_str::<Value>(body_preview) else {
        return Vec::new();
    };

    match value {
        Value::Object(map) => map
            .into_iter()
            .map(|(k, v)| ParsedBodyField {
                key: k,
                value_preview: truncate(&v.to_string(), 120),
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn parse_query_map(raw: Option<&str>) -> HashMap<String, String> {
    let Some(raw) = raw else {
        return HashMap::new();
    };

    raw.split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or_default().to_string();
            Some((key, value))
        })
        .collect()
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
}

fn api_key_hash_from_headers(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let value = header_value(headers, &state.config.auth.header_name)?;
    Some(hash_value(&value))
}

pub fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)[..24].to_string()
}

pub fn parse_jwt_claims(headers: &HeaderMap) -> Option<HashMap<String, Value>> {
    let raw = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())?
        .trim();

    let token = raw.strip_prefix("Bearer ")?.trim();
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let decoded = URL_SAFE_NO_PAD.decode(payload.as_bytes()).ok()?;
    let json: Value = serde_json::from_slice(&decoded).ok()?;
    let map = json.as_object()?.clone();
    Some(map.into_iter().collect())
}

fn as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(v) => Some(v.clone()),
        Value::Number(v) => Some(v.to_string()),
        _ => None,
    }
}

fn matches_kind(value: &Value, kind: &SchemaFieldKind) -> bool {
    match kind {
        SchemaFieldKind::Any => true,
        SchemaFieldKind::String => value.is_string(),
        SchemaFieldKind::Number => value.is_number(),
        SchemaFieldKind::Boolean => value.is_boolean(),
        SchemaFieldKind::Object => value.is_object(),
        SchemaFieldKind::Array => value.is_array(),
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn json_field_count(value: &Value) -> usize {
    match value {
        Value::Array(items) => items.iter().map(json_field_count).sum(),
        Value::Object(map) => map.len() + map.values().map(json_field_count).sum::<usize>(),
        _ => 0,
    }
}

pub fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }

    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}
