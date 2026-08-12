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
    pub route_overrides: Vec<RoutePolicyOverride>,
    pub route_rate_limits: Vec<RouteRateLimitOverride>,
    #[serde(default)]
    pub route_behavior_overrides: Vec<RouteBehaviorOverride>,
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
        if !self.telemetry_enabled {
            return Ok(());
        }

        if self.ingestion_url.trim().is_empty() {
            bail!("control-plane telemetry is enabled but ingestion_url is missing");
        }

        if self.api_key.trim().is_empty() {
            bail!("control-plane telemetry is enabled but api_key is missing");
        }

        if self.firewall_instance_id.trim().is_empty() {
            bail!("control-plane telemetry is enabled but firewall_instance_id is missing");
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    DetectOnly,
    Recommend,
    Block,
}

impl Default for RuleMode {
    fn default() -> Self {
        Self::DetectOnly
    }
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
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            shadow_min_hits: default_shadow_min_hits(),
        }
    }
}

fn default_shadow_min_hits() -> u64 {
    3
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

fn parse_bool_env(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enabled"
    )
}

fn is_known_placeholder_secret(value: &str) -> bool {
    matches!(
        value.trim(),
        "" | "dev-admin-token-1" | "replace-me-admin-token" | "replace-me-in-production"
    )
}
