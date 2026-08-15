use std::{collections::HashMap, net::IpAddr};

use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode},
};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    storage,
    types::{
        AppState, DecisionOutcome, MitigationAction, OperatorActionCommand, OperatorActionKind,
        Recommendation, RequestContext, SecurityDecision, SourceReputation,
    },
};

#[derive(Debug, Clone)]
pub struct ActiveMitigation {
    pub action_id: String,
    pub source_ip: IpAddr,
    pub action: MitigationAction,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct TemporaryMitigationStore {
    blocks: DashMap<IpAddr, ActiveMitigation>,
    reputation: DashMap<IpAddr, SourceReputationEntry>,
}

#[derive(Debug, Clone)]
struct SourceReputationEntry {
    suspicious_score: i32,
    last_seen_at: DateTime<Utc>,
}

impl TemporaryMitigationStore {
    pub fn get_active_block(&self, ip: &IpAddr) -> Option<ActiveMitigation> {
        let entry = self.blocks.get(ip)?;
        let mitigation = entry.value().clone();

        if mitigation.expires_at <= Utc::now() {
            drop(entry);
            self.blocks.remove(ip);
            return None;
        }

        Some(mitigation)
    }

    pub fn block_ip_for(&self, ip: IpAddr, seconds: u64, reason: String) -> ActiveMitigation {
        let mitigation = ActiveMitigation {
            action_id: Uuid::new_v4().to_string(),
            source_ip: ip,
            action: MitigationAction::BlockSourceIpTemporary { ttl_secs: seconds },
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(seconds as i64),
            reason,
        };

        self.blocks.insert(ip, mitigation.clone());
        mitigation
    }

    pub fn cleanup_expired(&self) -> Vec<IpAddr> {
        let now = Utc::now();
        let expired: Vec<IpAddr> = self
            .blocks
            .iter()
            .filter_map(|entry| {
                if entry.value().expires_at <= now {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        for ip in &expired {
            self.blocks.remove(ip);
        }

        expired
    }

    pub fn active_block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn list_active_blocks(&self) -> Vec<ActiveMitigation> {
        let now = Utc::now();
        self.blocks
            .iter()
            .filter_map(|entry| {
                let mitigation = entry.value().clone();
                if mitigation.expires_at > now {
                    Some(mitigation)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn unblock_ip(&self, ip: IpAddr) -> bool {
        self.blocks.remove(&ip).is_some()
    }

    pub fn add_suspicious_score(&self, ip: IpAddr, delta: i32) -> SourceReputation {
        let now = Utc::now();
        let score = match self.reputation.get_mut(&ip) {
            Some(mut entry) => {
                entry.suspicious_score += delta;
                entry.last_seen_at = now;
                entry.suspicious_score
            }
            None => {
                self.reputation.insert(
                    ip,
                    SourceReputationEntry {
                        suspicious_score: delta,
                        last_seen_at: now,
                    },
                );
                delta
            }
        };

        SourceReputation {
            source_ip: ip.to_string(),
            suspicious_score: score,
            last_seen_at: now,
        }
    }

    pub fn get_reputation(&self, ip: IpAddr) -> SourceReputation {
        if let Some(entry) = self.reputation.get(&ip) {
            return SourceReputation {
                source_ip: ip.to_string(),
                suspicious_score: entry.suspicious_score,
                last_seen_at: entry.last_seen_at,
            };
        }

        SourceReputation {
            source_ip: ip.to_string(),
            suspicious_score: 0,
            last_seen_at: Utc::now(),
        }
    }

    pub fn list_reputations(&self) -> Vec<SourceReputation> {
        self.reputation
            .iter()
            .map(|entry| SourceReputation {
                source_ip: entry.key().to_string(),
                suspicious_score: entry.value().suspicious_score,
                last_seen_at: entry.value().last_seen_at,
            })
            .collect()
    }

    pub fn insert_block_hydrated(&self, mitigation: ActiveMitigation) {
        self.blocks.insert(mitigation.source_ip, mitigation);
    }

    pub fn insert_reputation_hydrated(&self, reputation: SourceReputation) {
        if let Ok(ip) = reputation.source_ip.parse::<IpAddr>() {
            self.reputation.insert(
                ip,
                SourceReputationEntry {
                    suspicious_score: reputation.suspicious_score,
                    last_seen_at: reputation.last_seen_at,
                },
            );
        }
    }

    pub fn reset_reputation(&self, ip: IpAddr) -> bool {
        self.reputation.remove(&ip).is_some()
    }
}

pub fn finalize_blocking_decision(
    state: &AppState,
    context: &RequestContext,
    decision: SecurityDecision,
) -> Response<Body> {
    let reputation_delta = calculate_reputation_delta(&decision);
    let _reputation = if reputation_delta > 0 {
        let rep = state
            .mitigation_store
            .add_suspicious_score(context.source_ip, reputation_delta);

        if let Err(err) = storage::upsert_reputation(&state.config.storage.sqlite_path, &rep) {
            error!(error = %err, "failed to persist reputation");
        }

        Some(rep)
    } else {
        None
    };

    for action in &decision.actions {
        if let MitigationAction::BlockSourceIpTemporary { ttl_secs } = action {
            let mitigation = state.mitigation_store.block_ip_for(
                context.source_ip,
                *ttl_secs,
                decision.summary.clone(),
            );

            if let Err(err) =
                storage::upsert_active_mitigation(&state.config.storage.sqlite_path, &mitigation)
            {
                error!(error = %err, "failed to persist active mitigation");
            }

            warn!(
                request_id = %context.request_id,
                source_ip = %context.source_ip,
                action_id = %mitigation.action_id,
                ttl_secs = ttl_secs,
                "temporary IP block applied"
            );
        }
    }

    let (status, body) = match &decision.outcome {
        DecisionOutcome::Reject {
            status_code,
            message,
        } => {
            let status = StatusCode::from_u16(*status_code).unwrap_or(StatusCode::FORBIDDEN);
            (status, message.clone())
        }
        DecisionOutcome::Allow => (StatusCode::OK, "allowed".to_string()),
    };

    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;

    if let Ok(value) = HeaderValue::from_str(&context.request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    response
}

pub fn apply_manual_block(
    state: &AppState,
    ip: IpAddr,
    ttl_secs: u64,
    reason: String,
) -> anyhow::Result<ActiveMitigation> {
    let mitigation = state.mitigation_store.block_ip_for(ip, ttl_secs, reason);
    storage::upsert_active_mitigation(&state.config.storage.sqlite_path, &mitigation)?;
    Ok(mitigation)
}

pub fn reset_reputation_for_ip(state: &AppState, ip: IpAddr) -> anyhow::Result<bool> {
    let removed = state.mitigation_store.reset_reputation(ip);
    if removed {
        storage::delete_reputation(&state.config.storage.sqlite_path, &ip.to_string())?;
    }
    Ok(removed)
}

pub fn clear_source_state(state: &AppState, ip: IpAddr) -> anyhow::Result<(bool, bool)> {
    let block_removed = state.mitigation_store.unblock_ip(ip);
    if block_removed {
        storage::delete_active_mitigation(&state.config.storage.sqlite_path, &ip.to_string())?;
    }

    let reputation_removed = state.mitigation_store.reset_reputation(ip);
    if reputation_removed {
        storage::delete_reputation(&state.config.storage.sqlite_path, &ip.to_string())?;
    }

    let _cleared_memory = state.rate_limiter.clear_source_state(ip);

    Ok((block_removed, reputation_removed))
}

pub fn apply_non_blocking_effects(
    state: &AppState,
    context: &RequestContext,
    decision: &SecurityDecision,
) {
    let reputation_delta = calculate_reputation_delta(decision);
    if reputation_delta > 0 {
        let rep = state
            .mitigation_store
            .add_suspicious_score(context.source_ip, reputation_delta);
        if let Err(err) = storage::upsert_reputation(&state.config.storage.sqlite_path, &rep) {
            error!(error = %err, "failed to persist reputation (non-blocking)");
        }
    }
}

pub fn demo_recommendations() -> Vec<Recommendation> {
    vec![
        Recommendation {
            action_key: "block_ip_temporary".to_string(),
            title: "Temporarily block suspicious source IP".to_string(),
            rationale: "Source has exceeded suspicious score threshold.".to_string(),
            risk: "Low — reversible action with TTL.".to_string(),
            rollback_hint: "Use unblock endpoint to remove before TTL expires.".to_string(),
            parameters: hashmap(vec![
                ("source_ip".to_string(), "127.0.0.1".to_string()),
                ("ttl_secs".to_string(), "900".to_string()),
            ]),
        },
        Recommendation {
            action_key: "reset_reputation".to_string(),
            title: "Reset source reputation after review".to_string(),
            rationale: "Analyst confirmed source is benign.".to_string(),
            risk: "Low — clears accumulated score only.".to_string(),
            rollback_hint: "Score will re-accumulate on future violations.".to_string(),
            parameters: hashmap(vec![("source_ip".to_string(), "127.0.0.1".to_string())]),
        },
    ]
}

pub fn recommendation_to_command(rec: &Recommendation) -> Option<OperatorActionCommand> {
    let (kind, reversible) = match rec.action_key.as_str() {
        "block_ip_temporary" => (OperatorActionKind::BlockIpTemporary, true),
        "reset_reputation" => (OperatorActionKind::ResetReputation, false),
        _ => return None,
    };

    Some(OperatorActionCommand {
        kind,
        title: rec.title.clone(),
        rationale: rec.rationale.clone(),
        reversible,
        parameters: rec.parameters.clone(),
    })
}

fn calculate_reputation_delta(decision: &SecurityDecision) -> i32 {
    let mut score = 0;

    for finding in &decision.findings {
        score += match finding.severity {
            crate::types::Severity::Low => 1,
            crate::types::Severity::Medium => 2,
            crate::types::Severity::High => 4,
            crate::types::Severity::Critical => 6,
        };
    }

    score
}

fn hashmap(entries: Vec<(String, String)>) -> HashMap<String, String> {
    entries.into_iter().collect()
}
