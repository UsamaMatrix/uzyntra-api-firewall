use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    config::ControlPlaneConfig,
    types::{AttackClass, DecisionOutcome, MitigationAction, SecurityEvent, Severity},
};

const MAX_RETRIES: usize = 3;
const BASE_BACKOFF_MS: u64 = 100;
const MAX_BACKOFF_MS: u64 = 2_000;

#[derive(Clone)]
pub struct TelemetryDelivery {
    sender: Option<mpsc::Sender<SecurityEventIngestPayload>>,
    counters: Arc<TelemetryDeliveryCounters>,
    firewall_instance_id: String,
}

#[derive(Default)]
pub struct TelemetryDeliveryCounters {
    pub sent_total: AtomicU64,
    pub failed_total: AtomicU64,
    pub dropped_total: AtomicU64,
    pub retried_total: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventIngestPayload {
    pub firewall_instance_id: String,
    pub event_type: String,
    pub attack_type: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub request_path: Option<String>,
    pub http_method: Option<String>,
    pub user_agent: Option<String>,
    pub country: Option<String>,
    pub confidence: Option<f32>,
    pub detector_id: Option<String>,
    pub detector_ids: Vec<String>,
    pub score: Option<f32>,
    pub api_route_id: Option<String>,
    pub anomaly_type: Option<String>,
    pub action_taken: String,
    pub request_id: Option<String>,
    pub raw_metadata: serde_json::Value,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecurityEventMetadata {
    rule_ids: Vec<String>,
    detector_ids: Vec<String>,
    attack_classes: Vec<String>,
    categories: Vec<String>,
    scores: Vec<f32>,
    normalized_route: Option<String>,
    finding_count: usize,
    risk_score: f32,
    outcome: String,
    action_count: usize,
}

impl TelemetryDelivery {
    pub fn disabled() -> Self {
        Self {
            sender: None,
            counters: Arc::new(TelemetryDeliveryCounters::default()),
            firewall_instance_id: String::new(),
        }
    }

    pub fn new(config: &ControlPlaneConfig) -> Result<(Self, TelemetryDeliveryWorker)> {
        config.validate()?;

        if !config.telemetry_enabled {
            return Ok((
                Self::disabled(),
                TelemetryDeliveryWorker {
                    enabled: false,
                    receiver: None,
                    counters: Arc::new(TelemetryDeliveryCounters::default()),
                    client: Client::new(),
                    ingestion_url: String::new(),
                    api_key: String::new(),
                },
            ));
        }

        let capacity = config.queue_capacity.clamp(1, 100_000);
        let (sender, receiver) = mpsc::channel(capacity);
        let counters = Arc::new(TelemetryDeliveryCounters::default());
        let client = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms.max(1)))
            .user_agent("uzyntra-firewall-telemetry/0.1.0")
            .build()
            .context("failed to build control-plane telemetry HTTP client")?;

        Ok((
            Self {
                sender: Some(sender),
                counters: counters.clone(),
                firewall_instance_id: config.firewall_instance_id.clone(),
            },
            TelemetryDeliveryWorker {
                enabled: true,
                receiver: Some(receiver),
                counters,
                client,
                ingestion_url: config.ingestion_url.clone(),
                api_key: config.api_key.clone(),
            },
        ))
    }

    pub fn enqueue(&self, event: &SecurityEvent) {
        let Some(sender) = &self.sender else {
            return;
        };

        let payload = map_security_event(event, &self.firewall_instance_id);
        match sender.try_send(payload) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.counters.dropped_total.fetch_add(1, Ordering::Relaxed);
                warn!("control-plane telemetry queue full; dropped newest security event");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.counters.dropped_total.fetch_add(1, Ordering::Relaxed);
                warn!("control-plane telemetry worker unavailable; dropped security event");
            }
        }
    }

    pub fn snapshot(&self) -> TelemetryDeliverySnapshot {
        TelemetryDeliverySnapshot {
            sent_total: self.counters.sent_total.load(Ordering::Relaxed),
            failed_total: self.counters.failed_total.load(Ordering::Relaxed),
            dropped_total: self.counters.dropped_total.load(Ordering::Relaxed),
            retried_total: self.counters.retried_total.load(Ordering::Relaxed),
        }
    }
}

pub struct TelemetryDeliveryWorker {
    enabled: bool,
    receiver: Option<mpsc::Receiver<SecurityEventIngestPayload>>,
    counters: Arc<TelemetryDeliveryCounters>,
    client: Client,
    ingestion_url: String,
    api_key: String,
}

impl TelemetryDeliveryWorker {
    pub async fn run(mut self) {
        if !self.enabled {
            return;
        }

        let Some(mut receiver) = self.receiver.take() else {
            return;
        };

        info!("control-plane telemetry delivery worker started");
        while let Some(payload) = receiver.recv().await {
            if let Err(err) = deliver_with_retries(
                &self.client,
                &self.ingestion_url,
                &self.api_key,
                &payload,
                &self.counters,
            )
            .await
            {
                self.counters.failed_total.fetch_add(1, Ordering::Relaxed);
                warn!(error = %err, request_id = ?payload.request_id, "control-plane telemetry delivery failed");
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryDeliverySnapshot {
    pub sent_total: u64,
    pub failed_total: u64,
    pub dropped_total: u64,
    pub retried_total: u64,
}

pub fn map_security_event(
    event: &SecurityEvent,
    firewall_instance_id: &str,
) -> SecurityEventIngestPayload {
    let severity = highest_severity(event);
    let attack_type = primary_attack_type(event);
    let confidence = event
        .findings
        .iter()
        .map(|finding| finding.confidence)
        .reduce(f32::max);
    let primary = event.findings.iter().max_by(|a, b| {
        a.score()
            .partial_cmp(&b.score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let detector_ids: Vec<String> = event
        .findings
        .iter()
        .map(|finding| finding.detector_id().to_string())
        .collect();

    SecurityEventIngestPayload {
        firewall_instance_id: firewall_instance_id.to_owned(),
        event_type: "attack".to_string(),
        attack_type,
        severity,
        source_ip: Some(event.source_ip.clone()),
        request_path: Some(event.path.clone()),
        http_method: Some(event.method.clone()),
        user_agent: None,
        country: None,
        confidence,
        detector_id: primary.map(|finding| finding.detector_id().to_string()),
        detector_ids: detector_ids.clone(),
        score: primary.map(|finding| finding.score()),
        api_route_id: event.normalized_route.clone(),
        anomaly_type: primary.map(|finding| finding.category().to_string()),
        action_taken: action_taken(event),
        request_id: Some(event.request_id.clone()),
        raw_metadata: serde_json::to_value(SecurityEventMetadata {
            rule_ids: event
                .findings
                .iter()
                .map(|finding| finding.rule_id.clone())
                .collect(),
            detector_ids,
            attack_classes: event
                .findings
                .iter()
                .map(|finding| attack_class_name(&finding.attack_class))
                .collect(),
            categories: event
                .findings
                .iter()
                .map(|finding| finding.category().to_string())
                .collect(),
            scores: event
                .findings
                .iter()
                .map(|finding| finding.score())
                .collect(),
            normalized_route: event.normalized_route.clone(),
            finding_count: event.findings.len(),
            risk_score: event.decision.risk_score,
            outcome: outcome_name(&event.decision.outcome),
            action_count: event.decision.actions.len(),
        })
        .unwrap_or_else(|_| serde_json::json!({})),
        occurred_at: event.timestamp,
    }
}

async fn deliver_with_retries(
    client: &Client,
    ingestion_url: &str,
    api_key: &str,
    payload: &SecurityEventIngestPayload,
    counters: &TelemetryDeliveryCounters,
) -> Result<()> {
    let mut attempt = 0usize;

    loop {
        match deliver_once(client, ingestion_url, api_key, payload).await {
            Ok(DeliveryOutcome::Sent) => {
                counters.sent_total.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            Ok(DeliveryOutcome::Permanent(status)) => {
                bail!("control-plane rejected telemetry with non-retryable status {status}");
            }
            Ok(DeliveryOutcome::Retryable(status)) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    bail!("control-plane telemetry exhausted retries after status {status}");
                }
                counters.retried_total.fetch_add(1, Ordering::Relaxed);
                sleep_before_retry(attempt).await;
            }
            Err(err) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    return Err(err
                        .context("control-plane telemetry exhausted retries after network error"));
                }
                counters.retried_total.fetch_add(1, Ordering::Relaxed);
                sleep_before_retry(attempt).await;
            }
        }
    }
}

async fn deliver_once(
    client: &Client,
    ingestion_url: &str,
    api_key: &str,
    payload: &SecurityEventIngestPayload,
) -> Result<DeliveryOutcome> {
    let response = client
        .post(ingestion_url)
        .bearer_auth(api_key)
        .json(payload)
        .send()
        .await
        .context("control-plane telemetry request failed")?;

    let status = response.status();
    if status.is_success() {
        debug!(status = %status, "control-plane telemetry delivered");
        return Ok(DeliveryOutcome::Sent);
    }

    if is_retryable_status(status) {
        return Ok(DeliveryOutcome::Retryable(status));
    }

    Ok(DeliveryOutcome::Permanent(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryOutcome {
    Sent,
    Retryable(StatusCode),
    Permanent(StatusCode),
}

pub fn is_retryable_status(status: StatusCode) -> bool {
    status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

async fn sleep_before_retry(attempt: usize) {
    let capped = (BASE_BACKOFF_MS * 2u64.saturating_pow((attempt - 1) as u32)).min(MAX_BACKOFF_MS);
    let jitter = (attempt as u64 * 37) % 50;
    tokio::time::sleep(Duration::from_millis(capped + jitter)).await;
}

fn highest_severity(event: &SecurityEvent) -> String {
    event
        .findings
        .iter()
        .map(|finding| severity_rank(&finding.severity))
        .max()
        .map(rank_to_severity)
        .unwrap_or("low")
        .to_string()
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn rank_to_severity(rank: u8) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "medium",
        _ => "low",
    }
}

fn primary_attack_type(event: &SecurityEvent) -> String {
    event
        .findings
        .iter()
        .max_by_key(|finding| severity_rank(&finding.severity))
        .map(|finding| attack_class_name(&finding.attack_class))
        .unwrap_or_else(|| "unknown".to_string())
}

fn attack_class_name(class: &AttackClass) -> String {
    match class {
        AttackClass::SqlInjection => "sql_injection",
        AttackClass::Xss => "xss",
        AttackClass::CommandInjection => "command_injection",
        AttackClass::PathTraversal => "path_traversal",
        AttackClass::HeaderInjection => "header_injection",
        AttackClass::RequestSmuggling => "request_smuggling",
        AttackClass::Ssrf => "ssrf",
        AttackClass::BrokenAuthentication => "credential_attack",
        AttackClass::BruteForce => "credential_attack",
        AttackClass::RateLimitExceeded => "rate_limit_exceeded",
        AttackClass::MethodAbuse => "method_abuse",
        AttackClass::PayloadEvasion => "payload_evasion",
        AttackClass::MissingSecurityHeaders => "missing_security_headers",
        AttackClass::SchemaViolation => "schema_violation",
        AttackClass::JwtAbuse => "credential_attack",
        AttackClass::ObjectEnumeration => "object_enumeration",
        AttackClass::BehaviorAnomaly => "behavior_anomaly",
        AttackClass::ResponseLeak => "response_leak",
        AttackClass::ShadowApi => "shadow_api",
        AttackClass::TenantBoundaryViolation => "tenant_boundary_violation",
        AttackClass::ApiInventory => "api_inventory",
        AttackClass::AuthAbuse => "credential_attack",
        AttackClass::ResourceAbuse => "resource_abuse",
        AttackClass::SecurityMisconfiguration => "security_misconfiguration",
    }
    .to_string()
}

fn action_taken(event: &SecurityEvent) -> String {
    match event.decision.outcome {
        DecisionOutcome::Reject { .. } => "blocked".to_string(),
        DecisionOutcome::Allow => {
            if event
                .decision
                .actions
                .iter()
                .any(|action| matches!(action, MitigationAction::ThrottleSource { .. }))
            {
                "rate_limited".to_string()
            } else {
                "allowed".to_string()
            }
        }
    }
}

fn outcome_name(outcome: &DecisionOutcome) -> String {
    match outcome {
        DecisionOutcome::Allow => "allow".to_string(),
        DecisionOutcome::Reject { status_code, .. } => format!("reject:{status_code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::RuleMode,
        types::{Finding, FindingEvidence, SecurityDecision},
    };

    #[test]
    fn maps_security_event_to_control_plane_payload_without_secret_fields() {
        let event = sample_event(DecisionOutcome::Reject {
            status_code: 403,
            message: "blocked".to_string(),
        });

        let payload = map_security_event(&event, "firewall-1");

        assert_eq!(payload.firewall_instance_id, "firewall-1");
        assert_eq!(payload.event_type, "attack");
        assert_eq!(payload.attack_type, "sql_injection");
        assert_eq!(payload.severity, "high");
        assert_eq!(payload.action_taken, "blocked");
        assert_eq!(payload.request_id.as_deref(), Some("request-1"));

        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("authorization"));
        assert!(!json.contains("api_key"));
        assert!(!json.contains("password"));
    }

    #[test]
    fn retry_classification_matches_ingestion_contract() {
        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::FORBIDDEN));
    }

    #[tokio::test]
    async fn disabled_telemetry_does_not_enqueue() {
        let delivery = TelemetryDelivery::disabled();
        delivery.enqueue(&sample_event(DecisionOutcome::Allow));
        let snapshot = delivery.snapshot();
        assert_eq!(snapshot.dropped_total, 0);
        assert_eq!(snapshot.sent_total, 0);
    }

    #[test]
    fn full_queue_drops_newest_event() {
        let (sender, _receiver) = mpsc::channel(1);
        sender
            .try_send(map_security_event(
                &sample_event(DecisionOutcome::Allow),
                "fw",
            ))
            .unwrap();
        let delivery = TelemetryDelivery {
            sender: Some(sender),
            counters: Arc::new(TelemetryDeliveryCounters::default()),
            firewall_instance_id: "fw".to_string(),
        };

        delivery.enqueue(&sample_event(DecisionOutcome::Allow));

        assert_eq!(delivery.snapshot().dropped_total, 1);
    }

    fn sample_event(outcome: DecisionOutcome) -> SecurityEvent {
        SecurityEvent {
            request_id: "request-1".to_string(),
            timestamp: chrono::Utc::now(),
            source_ip: "203.0.113.10".to_string(),
            method: "POST".to_string(),
            path: "/api/orders".to_string(),
            normalized_route: Some("/api/{id}".to_string()),
            findings: vec![Finding {
                rule_id: "sqli.basic".to_string(),
                attack_class: AttackClass::SqlInjection,
                severity: Severity::High,
                confidence: 0.91,
                message: "SQL injection pattern".to_string(),
                evidence: vec![FindingEvidence {
                    location: "query".to_string(),
                    value_preview: "redacted-ish preview".to_string(),
                }],
                mode: RuleMode::Block,
            }],
            decision: SecurityDecision {
                outcome,
                actions: Vec::new(),
                recommendations: Vec::new(),
                findings: Vec::new(),
                summary: "test".to_string(),
                risk_score: 0.91,
            },
        }
    }
}
