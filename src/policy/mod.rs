use std::collections::HashSet;

use crate::{
    core,
    config::RuleMode,
    types::{
        AppState, AttackClass, DecisionOutcome, Finding, MitigationAction, Recommendation,
        RequestContext, SecurityDecision, Severity,
    },
};

pub fn evaluate_findings(
    state: &AppState,
    context: &RequestContext,
    findings: Vec<Finding>,
) -> SecurityDecision {
    if findings.is_empty() {
        return SecurityDecision {
            outcome: DecisionOutcome::Allow,
            actions: vec![],
            recommendations: vec![],
            findings,
            summary: "request allowed".into(),
            risk_score: 0.0,
        };
    }

    let reputation = state.mitigation_store.get_reputation(context.source_ip);
    let risk_score = core::calculate_risk(&findings, reputation.suspicious_score);

    let mut actions = Vec::new();
    let mut recommendations = Vec::new();
    let mut should_reject = false;

    for finding in &findings {
        match finding.mode {
            RuleMode::DetectOnly | RuleMode::Recommend => {
                recommendations.push(recommend_for_finding(finding));
            }
            RuleMode::Block => {
                apply_block_actions(state, finding, &mut actions, &mut recommendations);
                if matches!(finding.severity, Severity::High | Severity::Critical) {
                    should_reject = true;
                }
            }
        }
    }

    dedupe_actions(&mut actions);
    dedupe_recommendations(&mut recommendations);

    if risk_score >= 20.0 && findings.iter().any(|f| matches!(f.severity, Severity::Critical)) {
        should_reject = true;
    }

    let outcome = if should_reject {
        DecisionOutcome::Reject {
            status_code: 403,
            message: "request rejected by security policy".into(),
        }
    } else {
        DecisionOutcome::Allow
    };

    SecurityDecision {
        outcome,
        actions,
        recommendations,
        findings,
        summary: if should_reject {
            format!("request rejected (risk_score={risk_score:.2})")
        } else {
            format!("findings recorded without blocking (risk_score={risk_score:.2})")
        },
        risk_score,
    }
}

fn apply_block_actions(
    state: &AppState,
    finding: &Finding,
    actions: &mut Vec<MitigationAction>,
    recommendations: &mut Vec<Recommendation>,
) {
    match finding.attack_class {
        AttackClass::SqlInjection
        | AttackClass::CommandInjection
        | AttackClass::HeaderInjection
        | AttackClass::PathTraversal
        | AttackClass::Xss
        | AttackClass::BrokenAuthentication
        | AttackClass::JwtAbuse
        | AttackClass::SchemaViolation
        | AttackClass::TenantBoundaryViolation => {
            actions.push(MitigationAction::BlockRequest);
            actions.push(MitigationAction::MarkSourceSuspicious {
                ttl_secs: state.config.security.temp_suspicious_secs,
            });
        }
        AttackClass::BruteForce
        | AttackClass::RateLimitExceeded
        | AttackClass::BehaviorAnomaly
        | AttackClass::ObjectEnumeration => {
            actions.push(MitigationAction::ThrottleSource {
                ttl_secs: state.config.security.temp_suspicious_secs,
            });
        }
        AttackClass::PayloadEvasion => {
            actions.push(MitigationAction::MarkSourceSuspicious {
                ttl_secs: state.config.security.temp_suspicious_secs,
            });
        }
        AttackClass::MethodAbuse => {
            actions.push(MitigationAction::BlockRequest);
        }
        AttackClass::Ssrf
        | AttackClass::RequestSmuggling
        | AttackClass::MissingSecurityHeaders
        | AttackClass::ResponseLeak
        | AttackClass::ShadowApi => {
            recommendations.push(recommend_for_finding(finding));
        }
    }

    if matches!(finding.severity, Severity::Critical) {
        actions.push(MitigationAction::BlockSourceIpTemporary {
            ttl_secs: state.config.security.temp_ban_secs,
        });
    }
}

fn dedupe_actions(actions: &mut Vec<MitigationAction>) {
    let mut seen = HashSet::new();
    actions.retain(|action| seen.insert(action_key(action)));
}

fn action_key(action: &MitigationAction) -> String {
    match action {
        MitigationAction::BlockRequest => "BlockRequest".to_string(),
        MitigationAction::BlockSourceIpTemporary { ttl_secs } => {
            format!("BlockSourceIpTemporary:{ttl_secs}")
        }
        MitigationAction::ThrottleSource { ttl_secs } => {
            format!("ThrottleSource:{ttl_secs}")
        }
        MitigationAction::MarkSourceSuspicious { ttl_secs } => {
            format!("MarkSourceSuspicious:{ttl_secs}")
        }
    }
}

fn dedupe_recommendations(recommendations: &mut Vec<Recommendation>) {
    let mut seen = HashSet::new();
    recommendations.retain(|rec| seen.insert(rec.action_key.clone()));
}

fn recommend_for_finding(finding: &Finding) -> Recommendation {
    match finding.attack_class {
        AttackClass::SqlInjection => Recommendation {
            action_key: "review_input_validation".into(),
            title: "Review input validation and parameterization".into(),
            rationale: "SQL injection indicators suggest unsafe query construction or weak validation.".into(),
            risk: "Automatic permanent blocking can affect legitimate researchers or false positives.".into(),
            rollback_hint: "Use temporary controls first, then tune rule scope.".into(),
            parameters: Default::default(),
        },
        AttackClass::Xss => Recommendation {
            action_key: "tighten_output_encoding".into(),
            title: "Tighten output encoding and payload filtering".into(),
            rationale: "XSS indicators suggest reflected or stored script injection attempts.".into(),
            risk: "Aggressive generic filtering may overblock rich text workflows.".into(),
            rollback_hint: "Scope filtering to affected routes and content types.".into(),
            parameters: Default::default(),
        },
        AttackClass::CommandInjection => Recommendation {
            action_key: "isolate_command_surfaces".into(),
            title: "Review command execution surfaces".into(),
            rationale: "Command execution patterns are high risk and should be isolated or removed.".into(),
            risk: "Automatic response is usually safe, but root cause still requires manual review.".into(),
            rollback_hint: "Restore route after validation hardening and test coverage.".into(),
            parameters: Default::default(),
        },
        AttackClass::PathTraversal => Recommendation {
            action_key: "restrict_file_path_resolution".into(),
            title: "Restrict file path resolution".into(),
            rationale: "Traversal markers suggest unsafe file access path handling.".into(),
            risk: "Blocking is generally safe, but review file-serving routes carefully.".into(),
            rollback_hint: "Restore route-level exceptions only where explicitly needed.".into(),
            parameters: Default::default(),
        },
        AttackClass::HeaderInjection => Recommendation {
            action_key: "reject_crlf_payloads".into(),
            title: "Reject CRLF and header injection payloads".into(),
            rationale: "Header injection can lead to response splitting and downstream abuse.".into(),
            risk: "Low false-positive risk when evidence is strong.".into(),
            rollback_hint: "Keep rule enabled unless a verified compatibility issue exists.".into(),
            parameters: Default::default(),
        },
        AttackClass::RequestSmuggling => Recommendation {
            action_key: "review_proxy_header_handling".into(),
            title: "Review CL/TE and proxy header handling".into(),
            rationale: "Smuggling-like signals often need edge and upstream policy review.".into(),
            risk: "Automatic blocking can be noisy depending on deployment topology.".into(),
            rollback_hint: "Prefer detect/recommend mode until validated in staging.".into(),
            parameters: Default::default(),
        },
        AttackClass::Ssrf => Recommendation {
            action_key: "enforce_egress_allowlist".into(),
            title: "Enforce SSRF egress allowlist".into(),
            rationale: "SSRF-style targets should be restricted by explicit outbound policy.".into(),
            risk: "Automatic blocking can affect legitimate webhook and integration flows.".into(),
            rollback_hint: "Roll back per-route after allowlist tuning.".into(),
            parameters: Default::default(),
        },
        AttackClass::BrokenAuthentication | AttackClass::JwtAbuse => Recommendation {
            action_key: "review_auth_policy".into(),
            title: "Review auth policy for protected path".into(),
            rationale: "Protected route was accessed without valid credentials or token constraints.".into(),
            risk: "Automatic blocking is usually safe on admin or internal routes.".into(),
            rollback_hint: "Adjust protected path configuration or token validation policy.".into(),
            parameters: Default::default(),
        },
        AttackClass::BruteForce | AttackClass::RateLimitExceeded | AttackClass::BehaviorAnomaly => Recommendation {
            action_key: "enable_progressive_delay".into(),
            title: "Enable progressive delay or stricter throttling".into(),
            rationale: "Burst or anomalous activity suggests brute-force or abuse pressure.".into(),
            risk: "May increase friction for legitimate heavy users behind shared IPs.".into(),
            rollback_hint: "Use shorter TTLs and route-specific overrides.".into(),
            parameters: Default::default(),
        },
        AttackClass::MethodAbuse => Recommendation {
            action_key: "disable_unused_methods".into(),
            title: "Disable unused HTTP methods".into(),
            rationale: "Suspicious methods such as TRACE or CONNECT are rarely needed publicly.".into(),
            risk: "Can affect rare tooling or diagnostics if not scoped.".into(),
            rollback_hint: "Re-enable method only where explicitly needed.".into(),
            parameters: Default::default(),
        },
        AttackClass::PayloadEvasion => Recommendation {
            action_key: "increase_inspection_depth".into(),
            title: "Increase inspection depth for evasive sources".into(),
            rationale: "Encoding and mutation signals suggest bypass attempts.".into(),
            risk: "Stricter normalization can raise false positives.".into(),
            rollback_hint: "Reduce inspection depth after tuning signatures.".into(),
            parameters: Default::default(),
        },
        AttackClass::MissingSecurityHeaders => Recommendation {
            action_key: "add_security_headers".into(),
            title: "Add security headers upstream".into(),
            rationale: "Missing headers are a hardening issue, not necessarily an active exploit.".into(),
            risk: "Some headers may affect browser behavior if added broadly.".into(),
            rollback_hint: "Scope header policy to tested routes.".into(),
            parameters: Default::default(),
        },
        AttackClass::SchemaViolation => Recommendation {
            action_key: "tighten_api_schema".into(),
            title: "Tighten API schema enforcement".into(),
            rationale: "Schema drift or malformed requests suggest positive security gaps.".into(),
            risk: "Blocking unknown routes too aggressively can break undocumented integrations.".into(),
            rollback_hint: "Use detect mode first, then raise high-confidence routes to block.".into(),
            parameters: Default::default(),
        },
        AttackClass::ObjectEnumeration | AttackClass::TenantBoundaryViolation => Recommendation {
            action_key: "harden_object_authorization".into(),
            title: "Harden object and tenant authorization".into(),
            rationale: "Object or tenant-boundary abuse is one of the highest-impact API attack classes.".into(),
            risk: "Route-level exceptions may be required for trusted service accounts.".into(),
            rollback_hint: "Start with detect mode and validate route-object mapping before enforcement.".into(),
            parameters: Default::default(),
        },
        AttackClass::ResponseLeak => Recommendation {
            action_key: "inspect_response_contracts".into(),
            title: "Inspect upstream response contracts".into(),
            rationale: "Token, debug, or oversharing signals were detected in the response path.".into(),
            risk: "Aggressive masking can affect clients that depend on current response shape.".into(),
            rollback_hint: "Enable response inspection in detect mode before blocking.".into(),
            parameters: Default::default(),
        },
        AttackClass::ShadowApi => Recommendation {
            action_key: "review_shadow_routes".into(),
            title: "Review shadow or undocumented routes".into(),
            rationale: "Live traffic indicates routes not present in the declared API inventory.".into(),
            risk: "Some internal or canary routes may be intentionally undocumented.".into(),
            rollback_hint: "Whitelist validated internal routes in the spec database.".into(),
            parameters: Default::default(),
        },
    }
}