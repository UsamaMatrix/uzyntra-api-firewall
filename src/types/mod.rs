use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, RwLock},
};

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        AppConfig, PolicyMode, RouteBehaviorOverride, RoutePolicyOverride, RouteRateLimitOverride,
        RouteSensitivity, RuleMode, SpecUnknownRouteMode,
    },
    mitigation::TemporaryMitigationStore,
    rate_limit::RateLimiter,
    telemetry_delivery::TelemetryDelivery,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub proxy_client: Client,
    pub rate_limiter: Arc<RateLimiter>,
    pub mitigation_store: Arc<TemporaryMitigationStore>,
    pub policy_state: Arc<RwLock<LivePolicyState>>,
    pub telemetry_delivery: TelemetryDelivery,
    pub started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicyState {
    #[serde(default = "default_policy_version")]
    pub version: u64,
    #[serde(default)]
    pub previous_version: Option<u64>,
    #[serde(default)]
    pub policy_mode: PolicyMode,
    pub global_rule_modes: HashMap<String, RuleMode>,
    pub route_overrides: Vec<RoutePolicyOverride>,
    pub route_rate_limits: Vec<RouteRateLimitOverride>,
    pub route_behavior_overrides: Vec<RouteBehaviorOverride>,
    #[serde(default)]
    pub detector_exceptions: Vec<crate::config::DetectorException>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl LivePolicyState {
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            version: 1,
            previous_version: None,
            policy_mode: config.security.policy_mode.clone(),
            global_rule_modes: config.security.rule_modes.clone(),
            route_overrides: config.security.route_overrides.clone(),
            route_rate_limits: config.security.route_rate_limits.clone(),
            route_behavior_overrides: config.security.route_behavior_overrides.clone(),
            detector_exceptions: config.security.detector_exceptions.clone(),
            updated_at: Some(Utc::now()),
        }
    }
}

fn default_policy_version() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestContext {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub body_preview: Option<String>,
    pub parsed_body_fields: Vec<ParsedBodyField>,
    pub auth_status: AuthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBodyField {
    pub key: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthStatus {
    NotRequired,
    Satisfied,
    Missing,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackClass {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    HeaderInjection,
    RequestSmuggling,
    Ssrf,
    BrokenAuthentication,
    BruteForce,
    RateLimitExceeded,
    MethodAbuse,
    PayloadEvasion,
    MissingSecurityHeaders,
    SchemaViolation,
    JwtAbuse,
    ObjectEnumeration,
    BehaviorAnomaly,
    ResponseLeak,
    ShadowApi,
    TenantBoundaryViolation,
    ApiInventory,
    AuthAbuse,
    ResourceAbuse,
    SecurityMisconfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub location: String,
    pub value_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub attack_class: AttackClass,
    pub severity: Severity,
    pub confidence: f32,
    pub message: String,
    pub evidence: Vec<FindingEvidence>,
    pub mode: RuleMode,
}

impl Finding {
    pub fn detector_id(&self) -> &str {
        &self.rule_id
    }

    pub fn category(&self) -> &'static str {
        match self.attack_class {
            AttackClass::SqlInjection
            | AttackClass::Xss
            | AttackClass::CommandInjection
            | AttackClass::PathTraversal => "injection",
            AttackClass::Ssrf => "ssrf",
            AttackClass::BrokenAuthentication | AttackClass::JwtAbuse | AttackClass::AuthAbuse => {
                "authentication"
            }
            AttackClass::ObjectEnumeration | AttackClass::TenantBoundaryViolation => {
                "object_access"
            }
            AttackClass::SchemaViolation => "schema",
            AttackClass::ShadowApi | AttackClass::ApiInventory => "api_inventory",
            AttackClass::BehaviorAnomaly
            | AttackClass::RateLimitExceeded
            | AttackClass::BruteForce => "behavior",
            AttackClass::RequestSmuggling | AttackClass::HeaderInjection => "protocol",
            AttackClass::MissingSecurityHeaders | AttackClass::SecurityMisconfiguration => {
                "configuration"
            }
            AttackClass::ResponseLeak => "response_contract",
            AttackClass::ResourceAbuse => "resource_consumption",
            AttackClass::PayloadEvasion => "evasion",
            AttackClass::MethodAbuse => "method_abuse",
        }
    }

    pub fn score(&self) -> f32 {
        let severity = match self.severity {
            Severity::Low => 20.0,
            Severity::Medium => 45.0,
            Severity::High => 70.0,
            Severity::Critical => 90.0,
        };

        (severity * self.confidence.clamp(0.0, 1.0)).clamp(0.0, 100.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub action_key: String,
    pub title: String,
    pub rationale: String,
    pub risk: String,
    pub rollback_hint: String,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MitigationAction {
    BlockRequest,
    BlockSourceIpTemporary { ttl_secs: u64 },
    ThrottleSource { ttl_secs: u64 },
    MarkSourceSuspicious { ttl_secs: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecisionOutcome {
    Allow,
    Reject { status_code: u16, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityDecision {
    pub outcome: DecisionOutcome,
    #[serde(default)]
    pub actions: Vec<MitigationAction>,
    #[serde(default)]
    pub recommendations: Vec<Recommendation>,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub risk_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub request_id: String,
    pub timestamp: DateTime<Utc>,
    pub source_ip: String,
    pub method: String,
    pub path: String,
    pub findings: Vec<Finding>,
    pub decision: SecurityDecision,
    #[serde(default)]
    pub normalized_route: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceReputation {
    pub source_ip: String,
    pub suspicious_score: i32,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorActionKind {
    BlockIpTemporary,
    UnblockIp,
    TightenRouteRateLimit,
    SwitchRuleMode,
    ResetReputation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorActionCommand {
    pub kind: OperatorActionKind,
    pub title: String,
    pub rationale: String,
    pub reversible: bool,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAudit {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub details: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventSearchFilters {
    pub source_ip: Option<String>,
    pub rule_id: Option<String>,
    pub severity: Option<String>,
    pub method: Option<String>,
    pub path_contains: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditSearchFilters {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ManualBlockRequest {
    pub source_ip: String,
    pub ttl_secs: Option<u64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetGlobalRuleModeRequest {
    pub rule_id: String,
    pub mode: RuleMode,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpsertRouteOverrideRequest {
    pub path_prefix: String,
    pub rule_modes: HashMap<String, RuleMode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeleteRouteOverrideRequest {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpsertRouteRateLimitRequest {
    pub path_prefix: String,
    pub requests_per_window: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeleteRouteRateLimitRequest {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdminResponse<T: Serialize> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub fn ok<T: Serialize>(data: T) -> AdminResponse<T> {
    AdminResponse {
        ok: true,
        data: Some(data),
        error: None,
    }
}

pub fn err<T: Serialize>(message: impl Into<String>) -> AdminResponse<T> {
    AdminResponse {
        ok: false,
        data: None,
        error: Some(message.into()),
    }
}

pub fn resolve_rule_mode(state: &AppState, path: &str, rule_id: &str) -> RuleMode {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    for route_override in &guard.route_overrides {
        if path.starts_with(&route_override.path_prefix) {
            if let Some(mode) = route_override.rule_modes.get(rule_id) {
                return mode.clone();
            }
        }
    }

    guard
        .global_rule_modes
        .get(rule_id)
        .cloned()
        .unwrap_or(RuleMode::DetectOnly)
}

pub fn resolve_rate_limit_for_path(state: &AppState, path: &str) -> (String, u64, u64) {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    for route in &guard.route_rate_limits {
        if path.starts_with(&route.path_prefix) {
            return (
                route.path_prefix.clone(),
                route.requests_per_window,
                route.window_secs,
            );
        }
    }

    (
        "default".to_string(),
        state.config.security.rate_limit.requests_per_window,
        state.config.security.rate_limit.window_secs,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PrincipalKey {
    TenantUser(String, String),
    JwtSub(String),
    ApiKeyHash(String),
    Ip(String),
}

impl PrincipalKey {
    pub fn as_rate_limit_key(&self) -> String {
        match self {
            Self::TenantUser(tenant, user) => format!("tenant_user:{tenant}:{user}"),
            Self::JwtSub(sub) => format!("jwt_sub:{sub}"),
            Self::ApiKeyHash(hash) => format!("api_key:{hash}"),
            Self::Ip(ip) => format!("ip:{ip}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedRequestContext {
    pub request: RequestContext,
    pub normalized_path: String,
    pub normalized_route: String,
    pub principal: PrincipalKey,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub jwt_sub: Option<String>,
    pub api_key_hash: Option<String>,
    pub sensitivity: RouteSensitivity,
    pub required_scopes: Vec<String>,
    pub schema_mode: SpecUnknownRouteMode,
    pub object_id_candidates: Vec<String>,
    #[serde(default)]
    pub learned_route_hits: u64,
    #[serde(default)]
    pub request_content_type: Option<String>,
    #[serde(default)]
    pub request_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactors {
    pub schema_violation: f32,
    pub behavior_anomaly: f32,
    pub reputation: f32,
    pub token_risk: f32,
    pub object_abuse: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaValidationResult {
    pub allow: bool,
    pub finding: Option<Finding>,
    pub matched_route: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBehaviorSnapshot {
    pub principal_route_key: String,
    pub rps_samples: u64,
    pub mean_rps: f64,
    pub rps_stddev: f64,
    pub body_samples: u64,
    pub mean_body_size: f64,
    pub body_stddev: f64,
    pub recent_hits_1m: usize,
    pub distinct_object_ids_5m: usize,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedShadowRoute {
    pub method: String,
    pub normalized_path: String,
    pub approved_at: DateTime<Utc>,
    pub approved_by: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveShadowRouteRequest {
    pub method: String,
    pub normalized_path: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceAllowlistEntry {
    pub source_ip: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalAllowlistEntry {
    pub principal_prefix: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSourceAllowlistRequest {
    pub source_ip: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSourceAllowlistRequest {
    pub source_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertPrincipalAllowlistRequest {
    pub principal_prefix: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletePrincipalAllowlistRequest {
    pub principal_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicyExport {
    pub exported_at: DateTime<Utc>,
    #[serde(default = "default_policy_version")]
    pub version: u64,
    #[serde(default)]
    pub previous_version: Option<u64>,
    #[serde(default)]
    pub policy_mode: crate::config::PolicyMode,
    pub global_rule_modes: std::collections::HashMap<String, crate::config::RuleMode>,
    pub route_overrides: Vec<crate::config::RoutePolicyOverride>,
    pub route_rate_limits: Vec<crate::config::RouteRateLimitOverride>,
    pub route_behavior_overrides: Vec<crate::config::RouteBehaviorOverride>,
    #[serde(default)]
    pub detector_exceptions: Vec<crate::config::DetectorException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivePolicyImportRequest {
    #[serde(default)]
    pub policy_mode: Option<crate::config::PolicyMode>,
    pub global_rule_modes: std::collections::HashMap<String, crate::config::RuleMode>,
    pub route_overrides: Vec<crate::config::RoutePolicyOverride>,
    pub route_rate_limits: Vec<crate::config::RouteRateLimitOverride>,
    pub route_behavior_overrides: Vec<crate::config::RouteBehaviorOverride>,
    #[serde(default)]
    pub detector_exceptions: Vec<crate::config::DetectorException>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSpecRoute {
    pub method: String,
    pub normalized_path: String,
    pub managed_at: DateTime<Utc>,
    pub managed_by: String,
    pub auth_required: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteToManagedSpecRequest {
    pub method: String,
    pub normalized_path: String,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystSuppression {
    pub rule_id: String,
    pub path_prefix: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertSuppressionRequest {
    pub rule_id: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteSuppressionRequest {
    pub rule_id: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotedSpecRoute {
    pub method: String,
    pub normalized_path: String,
    pub promoted_at: DateTime<Utc>,
    pub promoted_by: String,
    pub source: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteShadowRouteRequest {
    pub method: String,
    pub normalized_path: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertRouteBehaviorOverrideRequest {
    pub path_prefix: String,
    #[serde(default)]
    pub warmup_min_samples: Option<u64>,
    #[serde(default)]
    pub object_enumeration_threshold: Option<usize>,
    #[serde(default)]
    pub object_window_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRouteBehaviorOverrideRequest {
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriScopedAllowlistEntry {
    pub source_ip: String,
    pub principal_prefix: String,
    pub path_prefix: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertTriScopedAllowlistRequest {
    pub source_ip: String,
    pub principal_prefix: String,
    pub path_prefix: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTriScopedAllowlistRequest {
    pub source_ip: String,
    pub principal_prefix: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleVerificationResult {
    pub bundle_id: String,
    pub verified_at: DateTime<Utc>,
    pub stored_digest_sha256: String,
    pub recomputed_digest_sha256: String,
    pub digest_match: bool,
    pub live_policy_digest_sha256: String,
    pub matches_live_policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementManagedSpecExport {
    pub exported_at: DateTime<Utc>,
    pub version: String,
    pub routes: Vec<EnforcementManagedRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementManagedRoute {
    pub method: String,
    pub normalized_path: String,
    pub auth_required: bool,
    #[serde(default)]
    pub expected_response: Option<EnforcementResponseContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementResponseContract {
    pub expected_status: u16,
    pub expected_content_type_prefix: String,
    #[serde(default)]
    pub required_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveContractMismatchRequest {
    pub method: String,
    pub normalized_path: String,
    pub expected_status: u16,
    pub expected_content_type_prefix: String,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedSourceAllowlistEntry {
    pub source_ip: String,
    pub path_prefix: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedPrincipalAllowlistEntry {
    pub principal_prefix: String,
    pub path_prefix: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertScopedSourceAllowlistRequest {
    pub source_ip: String,
    pub path_prefix: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteScopedSourceAllowlistRequest {
    pub source_ip: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertScopedPrincipalAllowlistRequest {
    pub principal_prefix: String,
    pub path_prefix: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteScopedPrincipalAllowlistRequest {
    pub principal_prefix: String,
    pub path_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    pub bundle_id: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub note: Option<String>,
    #[serde(default)]
    pub digest_sha256: String,
    pub live_policy: crate::types::LivePolicyExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSpecExport {
    pub exported_at: DateTime<Utc>,
    pub managed_spec_routes: Vec<crate::types::ManagedSpecRoute>,
    pub response_contracts: Vec<crate::types::ResponseContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseContract {
    pub method: String,
    pub normalized_path: String,
    pub expected_status: u16,
    pub expected_content_type_prefix: String,
    #[serde(default)]
    pub required_headers: Vec<String>,
    pub approved_at: DateTime<Utc>,
    pub approved_by: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertResponseContractRequest {
    pub method: String,
    pub normalized_path: String,
    pub expected_status: u16,
    pub expected_content_type_prefix: String,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponseContractRequest {
    pub method: String,
    pub normalized_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundle {
    pub bundle_id: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub note: Option<String>,
    #[serde(default)]
    pub digest_sha256: String,
    pub live_policy: crate::types::LivePolicyExport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePolicyBundleRequest {
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePolicyBundleRequest {
    pub bundle_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiffResult {
    pub compared_at: DateTime<Utc>,
    pub bundle_id: Option<String>,
    pub has_changes: bool,
    pub policy_mode_changed: bool,
    pub global_rule_modes_changed: bool,
    pub route_overrides_changed: bool,
    pub route_rate_limits_changed: bool,
    pub route_behavior_overrides_changed: bool,
    pub detector_exceptions_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRefusalEscalationRule {
    pub bundle_id: String,
    pub refusal_count: usize,
    pub severity: String,
    pub latest_timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseGuardResult {
    pub method: String,
    pub normalized_path: String,
    pub allowed: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KongRouteExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub services: Vec<KongServiceExport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KongServiceExport {
    pub name: String,
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub release_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyRouteExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub routes: Vec<EnvoyRouteRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvoyRouteRecord {
    pub match_path: String,
    pub method: String,
    pub auth_required: bool,
    #[serde(default)]
    pub release_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRecommendation {
    pub method: String,
    pub normalized_path: String,
    pub recommended_status: u16,
    pub recommended_content_type_prefix: String,
    #[serde(default)]
    pub recommended_required_headers: Vec<String>,
    pub supporting_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRecommendationSet {
    pub generated_at: DateTime<Utc>,
    pub items: Vec<ContractRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRefusalAlert {
    pub alert_id: String,
    pub created_at: DateTime<Utc>,
    pub bundle_id: String,
    pub severity: String,
    pub status: String,
    pub reason: String,
    pub stored_digest_sha256: String,
    pub recomputed_digest_sha256: String,
    pub latest_actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgeRestoreRefusalAlertRequest {
    pub alert_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRestoreRefusalAlertRequest {
    pub alert_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTimelineQuery {
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub target_contains: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub sort_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTimelinePage {
    pub items: Vec<PolicyTimelineEntry>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub sort_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteManagedSpecReleaseRequest {
    pub method: String,
    pub normalized_path: String,
    pub target_channel: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiGatewayPolicyExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub routes: Vec<ApiGatewayPolicyRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiGatewayPolicyRoute {
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub release_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportManifest {
    pub exported_at: DateTime<Utc>,
    pub managed_routes: usize,
    pub response_contracts: usize,
    pub release_state_records: usize,
    pub policy_bundles: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTimelineFilters {
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub target_contains: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreRefusalEvent {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub bundle_id: String,
    pub reason: String,
    pub stored_digest_sha256: String,
    pub recomputed_digest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedSpecReleaseState {
    pub method: String,
    pub normalized_path: String,
    pub channel: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertManagedSpecReleaseStateRequest {
    pub method: String,
    pub normalized_path: String,
    pub channel: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteManagedSpecReleaseStateRequest {
    pub method: String,
    pub normalized_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayExportVariantRequest {
    pub variant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRoutingOnlyExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub routes: Vec<GatewayRoutingOnlyRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRoutingOnlyRoute {
    pub method: String,
    pub path: String,
    pub auth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEnforcementExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub routes: Vec<GatewayEnforcementRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEnforcementRoute {
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    #[serde(default)]
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub expected_content_type_prefix: Option<String>,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub release_channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperPolicyBundleRequest {
    pub bundle_id: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRoutePolicyExport {
    pub method: String,
    pub path: String,
    pub auth_required: bool,
    #[serde(default)]
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub expected_content_type_prefix: Option<String>,
    #[serde(default)]
    pub required_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayManagedSpecExport {
    pub exported_at: DateTime<Utc>,
    pub schema_version: String,
    pub routes: Vec<GatewayRoutePolicyExport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveContractFromEventRequest {
    pub request_id: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTimelineEntry {
    pub timestamp: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedRoute {
    pub method: String,
    pub normalized_path: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hits: u64,
    pub has_auth: bool,
    #[serde(default)]
    pub request_content_types: Vec<String>,
    #[serde(default)]
    pub response_content_types: Vec<String>,
    #[serde(default)]
    pub observed_status_codes: Vec<u16>,
    #[serde(default)]
    pub min_request_bytes: Option<usize>,
    #[serde(default)]
    pub max_request_bytes: Option<usize>,
    #[serde(default)]
    pub min_response_bytes: Option<usize>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
    #[serde(default)]
    pub status: ApiInventoryStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApiInventoryStatus {
    #[default]
    New,
    Known,
    Approved,
    Deprecated,
    Unknown,
}
