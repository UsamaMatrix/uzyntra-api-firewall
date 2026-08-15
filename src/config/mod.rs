use std::{collections::HashMap, env, fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub proxy: ProxyConfig,
    pub security: SecurityConfig,
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    #[serde(default)]
    pub spec: SpecConfig,
    #[serde(default)]
    pub jwt: JwtConfig,
    #[serde(default)]
    pub behavior: BehaviorConfig,
    #[serde(default)]
    pub response_security: ResponseSecurityConfig,
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub public_bind_addr: String,
    pub admin_bind_addr: String,
    pub trust_x_forwarded_for: bool,
    pub environment: String,
    pub admin_public_health_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub upstream_base_url: String,
    pub connect_timeout_secs: u64,
    pub request_timeout_secs: u64,
    pub pool_idle_timeout_secs: u64,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub blocked_methods: Vec<String>,
    pub request_id_header: String,
    pub inspect_headers: bool,
    pub inspect_query_string: bool,
    pub inspect_body: bool,
    pub max_inspection_body_bytes: usize,
    pub temp_ban_secs: u64,
    pub temp_suspicious_secs: u64,
    pub suspicious_score_threshold: i32,
    pub rate_limit: RateLimitConfig,
    pub rule_modes: HashMap<String, RuleMode>,
    #[serde(default)]
    pub policy_mode: PolicyMode,
    #[serde(default = "default_min_block_confidence")]
    pub min_block_confidence: f32,
    #[serde(default = "default_min_block_score")]
    pub min_block_score: f32,
    #[serde(default)]
    pub detector_exceptions: Vec<DetectorException>,
    pub route_overrides: Vec<RoutePolicyOverride>,
    pub route_rate_limits: Vec<RouteRateLimitOverride>,
    #[serde(default)]
    pub route_behavior_overrides: Vec<RouteBehaviorOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Monitor,
    #[default]
    Balanced,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectorException {
    pub detector_id: String,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub parameter: Option<String>,
    #[serde(default)]
    pub min_confidence: Option<f32>,
    #[serde(default)]
    pub monitor_only: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_min_block_confidence() -> f32 {
    0.85
}

fn default_min_block_score() -> f32 {
    65.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_window: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub security_event_log_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    #[serde(default)]
    pub telemetry_enabled: bool,
    #[serde(default)]
    pub enrollment_enabled: bool,
    #[serde(default)]
    pub enrollment_url: String,
    #[serde(default)]
    pub enrollment_token: String,
    #[serde(default)]
    pub installation_identifier: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub ingestion_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub firewall_instance_id: String,
    #[serde(default = "default_control_plane_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_control_plane_queue_capacity")]
    pub queue_capacity: usize,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            telemetry_enabled: false,
            enrollment_enabled: false,
            enrollment_url: String::new(),
            enrollment_token: String::new(),
            installation_identifier: String::new(),
            hostname: String::new(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            region: String::new(),
            ingestion_url: String::new(),
            api_key: String::new(),
            firewall_instance_id: String::new(),
            request_timeout_ms: default_control_plane_request_timeout_ms(),
            queue_capacity: default_control_plane_queue_capacity(),
        }
    }
}

impl ControlPlaneConfig {
    pub fn validate(&self) -> Result<()> {
        if self.enrollment_enabled {
            if self.enrollment_url.trim().is_empty() {
                bail!("control-plane enrollment is enabled but enrollment_url is missing");
            }

            if self.enrollment_token.trim().is_empty() {
                bail!("control-plane enrollment is enabled but enrollment_token is missing");
            }
        }

        if self.telemetry_enabled {
            if self.ingestion_url.trim().is_empty() {
                bail!("control-plane telemetry is enabled but ingestion_url is missing");
            }

            if self.api_key.trim().is_empty() && !self.enrollment_enabled {
                bail!("control-plane telemetry is enabled but api_key is missing");
            }

            if self.firewall_instance_id.trim().is_empty() && !self.enrollment_enabled {
                bail!("control-plane telemetry is enabled but firewall_instance_id is missing");
            }
        }

        if self.request_timeout_ms == 0 || self.request_timeout_ms > 30_000 {
            bail!("control-plane telemetry request_timeout_ms must be between 1 and 30000");
        }

        if self.queue_capacity == 0 || self.queue_capacity > 100_000 {
            bail!("control-plane telemetry queue_capacity must be between 1 and 100000");
        }

        Ok(())
    }
}

fn default_control_plane_request_timeout_ms() -> u64 {
    5_000
}

fn default_control_plane_queue_capacity() -> usize {
    1_024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub sqlite_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub header_name: String,
    pub api_keys: Vec<String>,
    pub protected_path_prefixes: Vec<String>,
    pub admin: AdminAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAuthConfig {
    pub enabled: bool,
    pub header_name: String,
    pub token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    #[default]
    DetectOnly,
    Recommend,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RoutePolicyOverride {
    pub path_prefix: String,
    pub rule_modes: HashMap<String, RuleMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteBehaviorOverride {
    pub path_prefix: String,
    #[serde(default)]
    pub warmup_min_samples: Option<u64>,
    #[serde(default)]
    pub object_enumeration_threshold: Option<usize>,
    #[serde(default)]
    pub object_window_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RouteRateLimitOverride {
    pub path_prefix: String,
    pub requests_per_window: u64,
    pub window_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub unknown_route_mode: SpecUnknownRouteMode,
    #[serde(default)]
    pub routes: Vec<ConfiguredRouteSpec>,
}

impl Default for SpecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            unknown_route_mode: SpecUnknownRouteMode::Detect,
            routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SpecUnknownRouteMode {
    Allow,
    #[default]
    Detect,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredRouteSpec {
    pub method: String,
    pub path_template: String,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub required_headers: Vec<String>,
    #[serde(default)]
    pub required_query: Vec<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub sensitivity: RouteSensitivity,
    #[serde(default)]
    pub body: BodySchemaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RouteSensitivity {
    PublicLow,
    #[default]
    AuthenticatedStandard,
    SensitiveAccount,
    TenantAdmin,
    HighRiskExport,
    WriteCritical,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BodySchemaConfig {
    #[serde(default)]
    pub require_json: bool,
    #[serde(default)]
    pub required_fields: Vec<SchemaFieldConfig>,
    #[serde(default)]
    pub max_depth: usize,
    #[serde(default)]
    pub max_fields: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaFieldConfig {
    pub name: String,
    #[serde(default)]
    pub kind: SchemaFieldKind,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SchemaFieldKind {
    #[default]
    Any,
    String,
    Number,
    Boolean,
    Object,
    Array,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub expected_issuer: Option<String>,
    #[serde(default)]
    pub expected_audience: Option<String>,
    #[serde(default)]
    pub header_name: String,
    #[serde(default)]
    pub reject_alg_none: bool,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            expected_issuer: None,
            expected_audience: None,
            header_name: "authorization".to_string(),
            reject_alg_none: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_rps_spike_threshold")]
    pub rps_spike_threshold_z: f64,
    #[serde(default = "default_body_spike_threshold")]
    pub body_spike_threshold_z: f64,
    #[serde(default = "default_warmup_min_samples")]
    pub warmup_min_samples: u64,
    #[serde(default = "default_object_enumeration_threshold")]
    pub object_enumeration_threshold: usize,
    #[serde(default = "default_object_window_secs")]
    pub object_window_secs: u64,
    #[serde(default = "default_auth_attempt_window_secs")]
    pub auth_attempt_window_secs: u64,
    #[serde(default = "default_auth_bruteforce_threshold")]
    pub auth_bruteforce_threshold: usize,
    #[serde(default = "default_password_spray_threshold")]
    pub password_spray_threshold: usize,
    #[serde(default = "default_behavior_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_behavior_max_ids_per_entry")]
    pub max_ids_per_entry: usize,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rps_spike_threshold_z: default_rps_spike_threshold(),
            body_spike_threshold_z: default_body_spike_threshold(),
            warmup_min_samples: default_warmup_min_samples(),
            object_enumeration_threshold: default_object_enumeration_threshold(),
            object_window_secs: default_object_window_secs(),
            auth_attempt_window_secs: default_auth_attempt_window_secs(),
            auth_bruteforce_threshold: default_auth_bruteforce_threshold(),
            password_spray_threshold: default_password_spray_threshold(),
            max_entries: default_behavior_max_entries(),
            max_ids_per_entry: default_behavior_max_ids_per_entry(),
        }
    }
}

fn default_rps_spike_threshold() -> f64 {
    4.0
}

fn default_body_spike_threshold() -> f64 {
    5.0
}

fn default_warmup_min_samples() -> u64 {
    5
}

fn default_object_enumeration_threshold() -> usize {
    15
}

fn default_object_window_secs() -> u64 {
    300
}

fn default_auth_attempt_window_secs() -> u64 {
    300
}

fn default_auth_bruteforce_threshold() -> usize {
    8
}

fn default_password_spray_threshold() -> usize {
    5
}

fn default_behavior_max_entries() -> usize {
    10_000
}

fn default_behavior_max_ids_per_entry() -> usize {
    128
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSecurityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_json_fields: usize,
    #[serde(default)]
    pub mask_token_exposure: bool,
}

impl Default for ResponseSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_json_fields: 200,
            mask_token_exposure: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_shadow_min_hits")]
    pub shadow_min_hits: u64,
    #[serde(default = "default_max_learned_routes")]
    pub max_learned_routes: usize,
    #[serde(default = "default_schema_min_samples")]
    pub schema_min_samples: u64,
    #[serde(default = "default_max_schema_routes")]
    pub max_schema_routes: usize,
    #[serde(default = "default_max_schema_fields")]
    pub max_schema_fields: usize,
    #[serde(default = "default_max_json_depth")]
    pub max_json_depth: usize,
    #[serde(default = "default_max_json_array_len")]
    pub max_json_array_len: usize,
    #[serde(default = "default_max_query_params")]
    pub max_query_params: usize,
    #[serde(default = "default_max_normalized_bytes")]
    pub max_normalized_bytes: usize,
    #[serde(default = "default_max_decode_passes")]
    pub max_decode_passes: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shadow_min_hits: default_shadow_min_hits(),
            max_learned_routes: default_max_learned_routes(),
            schema_min_samples: default_schema_min_samples(),
            max_schema_routes: default_max_schema_routes(),
            max_schema_fields: default_max_schema_fields(),
            max_json_depth: default_max_json_depth(),
            max_json_array_len: default_max_json_array_len(),
            max_query_params: default_max_query_params(),
            max_normalized_bytes: default_max_normalized_bytes(),
            max_decode_passes: default_max_decode_passes(),
        }
    }
}

fn default_shadow_min_hits() -> u64 {
    3
}

fn default_max_learned_routes() -> usize {
    5_000
}

fn default_schema_min_samples() -> u64 {
    5
}

fn default_max_schema_routes() -> usize {
    2_000
}

fn default_max_schema_fields() -> usize {
    80
}

fn default_max_json_depth() -> usize {
    16
}

fn default_max_json_array_len() -> usize {
    200
}

fn default_max_query_params() -> usize {
    100
}

fn default_max_normalized_bytes() -> usize {
    16 * 1024
}

fn default_max_decode_passes() -> usize {
    2
}

impl AppConfig {
    pub fn load() -> Result<Self> {
        let config_path = env::var("APP_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config/development.yaml"));

        let raw = fs::read_to_string(&config_path)
            .with_context(|| format!("failed reading config file: {}", config_path.display()))?;

        let mut config: AppConfig = serde_yaml::from_str(&raw)
            .with_context(|| format!("failed parsing YAML config: {}", config_path.display()))?;

        if let Ok(public_bind_addr) = env::var("FIREWALL_PUBLIC_BIND_ADDR") {
            config.server.public_bind_addr = public_bind_addr;
        } else if let Ok(port) = env::var("PORT") {
            config.server.public_bind_addr = public_bind_addr_from_port_env(&port);
        }

        if let Ok(admin_bind_addr) = env::var("FIREWALL_ADMIN_BIND_ADDR") {
            config.server.admin_bind_addr = admin_bind_addr;
        }

        if let Ok(admin_token) = env::var("FIREWALL_ADMIN_TOKEN") {
            config.auth.admin.token = admin_token;
        }

        if let Ok(api_keys) = env::var("FIREWALL_API_KEYS") {
            config.auth.api_keys = api_keys
                .split(',')
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(ToOwned::to_owned)
                .collect();
        }

        if let Ok(upstream) = env::var("UPSTREAM_BASE_URL") {
            config.proxy.upstream_base_url = upstream;
        }

        if let Ok(log_level) = env::var("RUST_LOG") {
            config.telemetry.log_level = log_level;
        }

        if let Ok(enabled) = env::var("UZYNTRA_CONTROL_PLANE_TELEMETRY_ENABLED") {
            config.control_plane.telemetry_enabled = parse_bool_env(&enabled);
        }

        if let Ok(enabled) = env::var("UZYNTRA_CONTROL_PLANE_ENROLLMENT_ENABLED") {
            config.control_plane.enrollment_enabled = parse_bool_env(&enabled);
        }

        if let Ok(enrollment_url) = env::var("UZYNTRA_CONTROL_PLANE_ENROLLMENT_URL") {
            config.control_plane.enrollment_url = enrollment_url;
        }

        if let Ok(enrollment_token) = env::var("UZYNTRA_CONTROL_PLANE_ENROLLMENT_TOKEN") {
            config.control_plane.enrollment_token = enrollment_token;
        }

        if let Ok(installation_identifier) =
            env::var("UZYNTRA_CONTROL_PLANE_INSTALLATION_IDENTIFIER")
        {
            config.control_plane.installation_identifier = installation_identifier;
        }

        if let Ok(hostname) = env::var("UZYNTRA_CONTROL_PLANE_HOSTNAME") {
            config.control_plane.hostname = hostname;
        }

        if let Ok(version) = env::var("UZYNTRA_CONTROL_PLANE_VERSION") {
            config.control_plane.version = version;
        }

        if let Ok(region) = env::var("UZYNTRA_CONTROL_PLANE_REGION") {
            config.control_plane.region = region;
        }

        if let Ok(ingestion_url) = env::var("UZYNTRA_CONTROL_PLANE_INGEST_URL") {
            config.control_plane.ingestion_url = ingestion_url;
        }

        if let Ok(api_key) = env::var("UZYNTRA_CONTROL_PLANE_API_KEY") {
            config.control_plane.api_key = api_key;
        }

        if let Ok(firewall_instance_id) = env::var("UZYNTRA_FIREWALL_INSTANCE_ID") {
            config.control_plane.firewall_instance_id = firewall_instance_id;
        }

        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        self.control_plane.validate()?;

        if !(0.0..=1.0).contains(&self.security.min_block_confidence) {
            bail!("security.min_block_confidence must be between 0 and 1");
        }

        if !(0.0..=100.0).contains(&self.security.min_block_score) {
            bail!("security.min_block_score must be between 0 and 100");
        }

        for exception in &self.security.detector_exceptions {
            if exception.detector_id.trim().is_empty() {
                bail!("detector exception detector_id must not be empty");
            }

            if let Some(confidence) = exception.min_confidence {
                if !(0.0..=1.0).contains(&confidence) {
                    bail!("detector exception min_confidence must be between 0 and 1");
                }
            }

            if let Some(parameter) = &exception.parameter {
                validate_detector_exception_parameter(parameter)?;
            }
        }

        if self.discovery.max_decode_passes > 4 {
            bail!("discovery.max_decode_passes must be 4 or less");
        }

        if self.discovery.max_normalized_bytes == 0
            || self.discovery.max_normalized_bytes > 256 * 1024
        {
            bail!("discovery.max_normalized_bytes must be between 1 and 262144");
        }

        if !self.server.environment.eq_ignore_ascii_case("production") {
            return Ok(());
        }

        if self.auth.admin.enabled {
            let admin_token = self.auth.admin.token.trim();
            if admin_token.is_empty() {
                bail!("production config requires a non-empty admin token; set FIREWALL_ADMIN_TOKEN or auth.admin.token");
            }

            if is_known_placeholder_secret(admin_token) {
                bail!(
                    "production config refuses placeholder admin token; set FIREWALL_ADMIN_TOKEN to a production secret"
                );
            }
        }

        if self.auth.enabled {
            if self.auth.api_keys.is_empty() {
                bail!("production config requires at least one API key; set FIREWALL_API_KEYS or auth.api_keys");
            }

            if self
                .auth
                .api_keys
                .iter()
                .any(|key| is_known_placeholder_secret(key))
            {
                bail!(
                    "production config refuses placeholder API keys; set FIREWALL_API_KEYS to production secrets"
                );
            }
        }

        Ok(())
    }
}

fn validate_detector_exception_parameter(parameter: &str) -> Result<()> {
    if parameter.is_empty()
        || parameter.len() > 120
        || !parameter
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        bail!("security.detector_exceptions parameter selector is invalid");
    }

    Ok(())
}

fn parse_bool_env(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

fn public_bind_addr_from_port_env(port: &str) -> String {
    format!("0.0.0.0:{}", port.trim())
}

fn is_known_placeholder_secret(value: &str) -> bool {
    matches!(
        value.trim(),
        "" | "dev-admin-token-1" | "replace-me-admin-token" | "replace-me-in-production"
    )
}

#[cfg(test)]
mod tests {
    use super::public_bind_addr_from_port_env;

    #[test]
    fn derives_public_bind_addr_from_platform_port() {
        assert_eq!(public_bind_addr_from_port_env(" 12345 "), "0.0.0.0:12345");
    }
}
