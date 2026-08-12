use std::{
    collections::{HashSet, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

use axum::http::HeaderMap;
use dashmap::DashMap;
use serde::Serialize;

use crate::{
    core,
    types::{
        resolve_rate_limit_for_path, resolve_rule_mode, AppState, AttackClass, Finding,
        FindingEvidence, RequestContext, Severity,
    },
};

#[derive(Debug, Clone)]
struct RateState {
    count: u64,
    window_start: Instant,
}

#[derive(Debug, Clone)]
struct BehaviorState {
    rps_samples: u64,
    mean_rps: f64,
    m2_rps: f64,

    body_samples: u64,
    mean_body_size: f64,
    m2_body_size: f64,

    recent_hits: VecDeque<Instant>,
    recent_object_ids: VecDeque<(Instant, String)>,
}

impl Default for BehaviorState {
    fn default() -> Self {
        Self {
            rps_samples: 0,
            mean_rps: 0.0,
            m2_rps: 0.0,
            body_samples: 0,
            mean_body_size: 0.0,
            m2_body_size: 0.0,
            recent_hits: VecDeque::new(),
            recent_object_ids: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorBaselineSnapshot {
    pub principal_route_key: String,
    pub rps_samples: u64,
    pub mean_rps: f64,
    pub rps_stddev: f64,
    pub body_samples: u64,
    pub mean_body_size: f64,
    pub body_stddev: f64,
    pub recent_hits_1m: usize,
    pub distinct_object_ids_5m: usize,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    entries: DashMap<String, RateState>,
    behavior: DashMap<String, BehaviorState>,
}

impl RateLimiter {
    pub fn new(_limit: u64, _window_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
            behavior: DashMap::new(),
        }
    }

    pub fn check(&self, key: &str, limit: u64, window_secs: u64) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);

        match self.entries.get_mut(key) {
            Some(mut entry) => {
                if now.duration_since(entry.window_start) >= window {
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else {
                    entry.count += 1;
                    entry.count <= limit
                }
            }
            None => {
                self.entries.insert(
                    key.to_string(),
                    RateState {
                        count: 1,
                        window_start: now,
                    },
                );
                true
            }
        }
    }

    pub fn clear_source_state(&self, ip: IpAddr) -> usize {
        let prefix = format!("ip:{}|", ip);

        let rate_keys: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.key().clone())
            .collect();

        let behavior_keys: Vec<String> = self
            .behavior
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.key().clone())
            .collect();

        for key in &rate_keys {
            self.entries.remove(key);
        }

        for key in &behavior_keys {
            self.behavior.remove(key);
        }

        rate_keys.len() + behavior_keys.len()
    }

    pub fn clear_behavior_state(&self) -> usize {
        let keys: Vec<String> = self
            .behavior
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        for key in &keys {
            self.behavior.remove(key);
        }

        keys.len()
    }

    pub fn behavior_entry_count(&self) -> usize {
        self.behavior.len()
    }

    pub fn snapshot_behavior(&self, limit: usize) -> Vec<BehaviorBaselineSnapshot> {
        let mut items: Vec<_> = self
            .behavior
            .iter()
            .map(|entry| {
                let distinct_object_ids_5m: HashSet<String> = entry
                    .recent_object_ids
                    .iter()
                    .map(|(_, id)| id.clone())
                    .collect();

                BehaviorBaselineSnapshot {
                    principal_route_key: entry.key().clone(),
                    rps_samples: entry.rps_samples,
                    mean_rps: entry.mean_rps,
                    rps_stddev: stddev(entry.m2_rps, entry.rps_samples),
                    body_samples: entry.body_samples,
                    mean_body_size: entry.mean_body_size,
                    body_stddev: stddev(entry.m2_body_size, entry.body_samples),
                    recent_hits_1m: entry.recent_hits.len(),
                    distinct_object_ids_5m: distinct_object_ids_5m.len(),
                }
            })
            .collect();

        items.sort_by(|a, b| {
            b.recent_hits_1m
                .cmp(&a.recent_hits_1m)
                .then_with(|| b.distinct_object_ids_5m.cmp(&a.distinct_object_ids_5m))
        });

        items.into_iter().take(limit).collect()
    }
    pub fn snapshot_behavior_persistable(
        &self,
        limit: usize,
    ) -> Vec<crate::types::PersistedBehaviorSnapshot> {
        let now = chrono::Utc::now();
        self.snapshot_behavior(limit)
            .into_iter()
            .map(|item| crate::types::PersistedBehaviorSnapshot {
                principal_route_key: item.principal_route_key,
                rps_samples: item.rps_samples,
                mean_rps: item.mean_rps,
                rps_stddev: item.rps_stddev,
                body_samples: item.body_samples,
                mean_body_size: item.mean_body_size,
                body_stddev: item.body_stddev,
                recent_hits_1m: item.recent_hits_1m,
                distinct_object_ids_5m: item.distinct_object_ids_5m,
                captured_at: now,
            })
            .collect()
    }
}

pub fn evaluate_request(state: &AppState, context: &RequestContext) -> Vec<Finding> {
    let headers = HeaderMap::new();
    evaluate_request_with_headers(state, context, &headers)
}

pub fn evaluate_request_with_headers(
    state: &AppState,
    context: &RequestContext,
    headers: &HeaderMap,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let (bucket, limit, window_secs) = resolve_rate_limit_for_path(state, &context.path);
    let principal = core::derive_principal(state, context, headers);
    let principal_key = principal.as_rate_limit_key();
    let rate_key = format!("{}|{}", principal_key, bucket);

    let allowed = state.rate_limiter.check(&rate_key, limit, window_secs);
    if !allowed {
        findings.push(Finding {
            rule_id: "rate_limit.exceeded".into(),
            attack_class: AttackClass::RateLimitExceeded,
            severity: Severity::High,
            confidence: 0.99,
            message: format!(
                "rate limit exceeded for bucket '{}' ({} requests / {} seconds)",
                bucket, limit, window_secs
            ),
            evidence: vec![
                FindingEvidence {
                    location: "rate_limit.bucket".into(),
                    value_preview: bucket.clone(),
                },
                FindingEvidence {
                    location: "rate_limit.principal".into(),
                    value_preview: principal_key.clone(),
                },
            ],
            mode: resolve_rule_mode(state, &context.path, "rate_limit.exceeded"),
        });
    }

    if let Some(behavior_finding) = evaluate_behavior(state, context, &principal_key) {
        findings.push(behavior_finding);
    }

    if let Some(object_finding) = evaluate_object_enumeration(state, context, &principal_key) {
        findings.push(object_finding);
    }

    findings
}

fn resolve_route_behavior(state: &AppState, path: &str) -> (u64, usize, u64) {
    let guard = state.policy_state.read().expect("policy_state poisoned");

    for route in &guard.route_behavior_overrides {
        if path.starts_with(&route.path_prefix) {
            let warmup = route
                .warmup_min_samples
                .unwrap_or(state.config.behavior.warmup_min_samples);
            let threshold = route
                .object_enumeration_threshold
                .unwrap_or(state.config.behavior.object_enumeration_threshold);
            let window_secs = route
                .object_window_secs
                .unwrap_or(state.config.behavior.object_window_secs);

            return (warmup, threshold, window_secs);
        }
    }

    (
        state.config.behavior.warmup_min_samples,
        state.config.behavior.object_enumeration_threshold,
        state.config.behavior.object_window_secs,
    )
}

fn evaluate_behavior(
    state: &AppState,
    context: &RequestContext,
    principal_key: &str,
) -> Option<Finding> {
    if !state.config.behavior.enabled {
        return None;
    }

    let route_key = core::normalize_runtime_path(&core::canonical_security_path(&context.path));
    let (warmup_min_samples, _, object_window_secs) = resolve_route_behavior(state, &context.path);

    let key = format!("{}|{}", principal_key, route_key);
    let now = Instant::now();
    let body_size = context.body_preview.as_ref().map(|b| b.len()).unwrap_or(0) as f64;

    let mut entry = state.rate_limiter.behavior.entry(key).or_default();

    purge_old_hits(&mut entry.recent_hits, now, Duration::from_secs(60));
    purge_old_object_ids(
        &mut entry.recent_object_ids,
        now,
        Duration::from_secs(object_window_secs),
    );

    entry.recent_hits.push_back(now);
    let current_rps = entry.recent_hits.len() as f64;

    let mut triggered = None;

    let rps_stddev = stddev(entry.m2_rps, entry.rps_samples);
    let body_stddev = stddev(entry.m2_body_size, entry.body_samples);

    let rps_z = if entry.rps_samples >= warmup_min_samples {
        z_score(current_rps, entry.mean_rps, rps_stddev)
    } else {
        0.0
    };

    let body_z = if entry.body_samples >= warmup_min_samples {
        z_score(body_size, entry.mean_body_size, body_stddev)
    } else {
        0.0
    };

    let zero_variance_rps_jump = entry.rps_samples >= warmup_min_samples
        && rps_stddev <= 0.0001
        && entry.mean_rps >= 1.0
        && current_rps >= (entry.mean_rps * 2.0).max(entry.mean_rps + 3.0);

    let zero_variance_body_jump = entry.body_samples >= warmup_min_samples
        && body_stddev <= 0.0001
        && entry.mean_body_size >= 1.0
        && body_size >= (entry.mean_body_size * 1.8).max(entry.mean_body_size + 24.0);

    if rps_z >= state.config.behavior.rps_spike_threshold_z
        || body_z >= state.config.behavior.body_spike_threshold_z
        || zero_variance_rps_jump
        || zero_variance_body_jump
    {
        triggered = Some(Finding {
            rule_id: "behavior.anomaly".to_string(),
            attack_class: AttackClass::BehaviorAnomaly,
            severity: Severity::Medium,
            confidence: if zero_variance_rps_jump || zero_variance_body_jump { 0.84 } else { 0.78 },
            message: format!(
                "behavior anomaly detected (rps_z={:.2}, body_z={:.2}, zero_var_rps={}, zero_var_body={})",
                rps_z, body_z, zero_variance_rps_jump, zero_variance_body_jump
            ),
            evidence: vec![
                FindingEvidence {
                    location: "behavior.route".to_string(),
                    value_preview: route_key,
                },
                FindingEvidence {
                    location: "behavior.principal".to_string(),
                    value_preview: principal_key.to_string(),
                },
                FindingEvidence {
                    location: "behavior.body_size".to_string(),
                    value_preview: format!(
                        "current={}, mean={:.2}, stddev={:.4}",
                        body_size, entry.mean_body_size, body_stddev
                    ),
                },
            ],
            mode: resolve_rule_mode(state, &context.path, "behavior.anomaly"),
        });
    }

    let mut rps_samples = entry.rps_samples;
    let mut mean_rps = entry.mean_rps;
    let mut m2_rps = entry.m2_rps;
    update_welford(&mut rps_samples, &mut mean_rps, &mut m2_rps, current_rps);
    entry.rps_samples = rps_samples;
    entry.mean_rps = mean_rps;
    entry.m2_rps = m2_rps;

    let mut body_samples = entry.body_samples;
    let mut mean_body_size = entry.mean_body_size;
    let mut m2_body_size = entry.m2_body_size;
    update_welford(
        &mut body_samples,
        &mut mean_body_size,
        &mut m2_body_size,
        body_size,
    );
    entry.body_samples = body_samples;
    entry.mean_body_size = mean_body_size;
    entry.m2_body_size = m2_body_size;

    triggered
}

fn evaluate_object_enumeration(
    state: &AppState,
    context: &RequestContext,
    principal_key: &str,
) -> Option<Finding> {
    let ids = object_id_candidates(context);
    if ids.is_empty() {
        return None;
    }

    let route_key = core::normalize_runtime_path(&core::canonical_security_path(&context.path));
    let (_, object_threshold, object_window_secs) = resolve_route_behavior(state, &context.path);
    let key = format!("{}|{}", principal_key, route_key);
    let now = Instant::now();

    let mut entry = state.rate_limiter.behavior.entry(key).or_default();

    purge_old_object_ids(
        &mut entry.recent_object_ids,
        now,
        Duration::from_secs(object_window_secs),
    );
    for id in ids {
        entry.recent_object_ids.push_back((now, id));
    }

    let distinct_ids: HashSet<String> = entry
        .recent_object_ids
        .iter()
        .map(|(_, id)| id.clone())
        .collect();

    if distinct_ids.len() >= object_threshold {
        return Some(Finding {
            rule_id: "object.enumeration.window".to_string(),
            attack_class: AttackClass::ObjectEnumeration,
            severity: Severity::High,
            confidence: 0.82,
            message: format!(
                "high distinct object access volume detected ({} unique object IDs / {}s)",
                distinct_ids.len(),
                object_window_secs
            ),
            evidence: vec![
                FindingEvidence {
                    location: "object.enumeration.principal".to_string(),
                    value_preview: principal_key.to_string(),
                },
                FindingEvidence {
                    location: "object.enumeration.count".to_string(),
                    value_preview: distinct_ids.len().to_string(),
                },
            ],
            mode: resolve_rule_mode(state, &context.path, "object.enumeration.window"),
        });
    }

    None
}

fn purge_old_hits(queue: &mut VecDeque<Instant>, now: Instant, ttl: Duration) {
    while let Some(ts) = queue.front() {
        if now.duration_since(*ts) > ttl {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn purge_old_object_ids(queue: &mut VecDeque<(Instant, String)>, now: Instant, ttl: Duration) {
    while let Some((ts, _)) = queue.front() {
        if now.duration_since(*ts) > ttl {
            queue.pop_front();
        } else {
            break;
        }
    }
}

fn update_welford(samples: &mut u64, mean: &mut f64, m2: &mut f64, value: f64) {
    *samples += 1;
    let delta = value - *mean;
    *mean += delta / *samples as f64;
    let delta2 = value - *mean;
    *m2 += delta * delta2;
}

fn stddev(m2: f64, samples: u64) -> f64 {
    if samples < 2 {
        0.0
    } else {
        (m2 / (samples as f64 - 1.0)).sqrt()
    }
}

fn z_score(value: f64, mean: f64, stddev: f64) -> f64 {
    if stddev <= 0.0001 {
        0.0
    } else {
        (value - mean) / stddev
    }
}

fn object_id_candidates(context: &RequestContext) -> Vec<String> {
    let mut ids = Vec::new();

    for segment in context.path.split('/') {
        if is_object_id(segment) {
            ids.push(segment.to_string());
        }
    }

    if let Some(query) = &context.query {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default().to_ascii_lowercase();
            let value = parts.next().unwrap_or_default();
            if (key.ends_with("id") || key.ends_with("_id")) && !value.is_empty() {
                ids.push(value.to_string());
            }
        }
    }

    for field in &context.parsed_body_fields {
        let key = field.key.to_ascii_lowercase();
        if key.ends_with("id") || key.ends_with("_id") {
            ids.push(field.value_preview.clone());
        }
    }

    ids
}

fn is_object_id(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    if value.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    value.len() >= 8 && value.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}
