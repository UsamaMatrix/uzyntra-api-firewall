use std::collections::HashSet;

use axum::http::{HeaderMap, HeaderName};
use once_cell::sync::Lazy;
use regex::Regex;
use urlencoding::decode;

use crate::{
    core,
    types::{
        resolve_rule_mode, AppState, AttackClass, AuthStatus, EnrichedRequestContext, Finding,
        FindingEvidence, RequestContext, Severity,
    },
};

static SQLI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(union\s+select|information_schema|\bbenchmark\s*\(|\bsleep\s*\(|(?:'|")\s*or\s+(?:'|")?1(?:'|")?=(?:'|")?1)"#).unwrap()
});

static XSS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie|alert\s*\()")
        .unwrap()
});

static CMDI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(;\s*(cat|ls|id)\b|\|\s*(whoami|id)\b|&&\s*(whoami|id)\b|`[^`]+`|\$\([^\)]+\)|/bin/sh|cmd\.exe|powershell\.exe)")
        .unwrap()
});

static SSRF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254)|file://|gopher://)")
        .unwrap()
});

pub trait Detector: Send + Sync {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        headers: &HeaderMap,
    ) -> Vec<Finding>;
}

pub struct AuthDetector;
pub struct MethodDetector;
pub struct PathDetector;
pub struct BodyDetector;
pub struct HeaderDetector;
pub struct JwtSecurityDetector;
pub struct ObjectAbuseDetector;

pub fn inspect_request(
    state: &AppState,
    context: &RequestContext,
    headers: &HeaderMap,
) -> Vec<Finding> {
    let enriched = core::enrich_request(state, context, headers);
    let schema = core::validate_against_spec(state, &enriched, headers);

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(AuthDetector),
        Box::new(MethodDetector),
        Box::new(PathDetector),
        Box::new(HeaderDetector),
        Box::new(BodyDetector),
        Box::new(JwtSecurityDetector),
        Box::new(ObjectAbuseDetector),
    ];

    let mut findings = Vec::new();

    if let Some(finding) = schema.finding {
        findings.push(finding);
    }

    for detector in detectors {
        findings.extend(detector.detect(state, &enriched, headers));
    }

    findings
}

pub fn inspect_response(
    state: &AppState,
    context: &RequestContext,
    response_headers: &HeaderMap,
    response_body_preview: &str,
) -> Vec<Finding> {
    if !state.config.response_security.enabled {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let lower = response_body_preview.to_ascii_lowercase();

    if lower.contains("traceback")
        || lower.contains("stack trace")
        || lower.contains("exception:")
    {
        findings.push(Finding {
            rule_id: "response.debug_leak".to_string(),
            attack_class: AttackClass::ResponseLeak,
            severity: Severity::High,
            confidence: 0.95,
            message: "debug or exception material detected in upstream response".to_string(),
            evidence: vec![FindingEvidence {
                location: "response.body".to_string(),
                value_preview: core::truncate(response_body_preview, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "response.debug_leak"),
        });
    }

    if lower.contains("access_token") || lower.contains("refresh_token") {
        findings.push(Finding {
            rule_id: "response.token_exposure".to_string(),
            attack_class: AttackClass::ResponseLeak,
            severity: Severity::Critical,
            confidence: 0.96,
            message: "token-like material detected in upstream response".to_string(),
            evidence: vec![FindingEvidence {
                location: "response.body".to_string(),
                value_preview: core::truncate(response_body_preview, 200),
            }],
            mode: resolve_rule_mode(state, &context.path, "response.token_exposure"),
        });
    }

    if let Some(content_type) = response_headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase())
    {
        if content_type.contains("application/json") {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(response_body_preview) {
                let field_count = count_json_fields(&json);
                if field_count > state.config.response_security.max_json_fields {
                    findings.push(Finding {
                        rule_id: "response.oversharing".to_string(),
                        attack_class: AttackClass::ResponseLeak,
                        severity: Severity::Medium,
                        confidence: 0.75,
                        message: format!(
                            "response JSON field count {} exceeds configured threshold {}",
                            field_count, state.config.response_security.max_json_fields
                        ),
                        evidence: vec![FindingEvidence {
                            location: "response.body".to_string(),
                            value_preview: format!("json_field_count={field_count}"),
                        }],
                        mode: resolve_rule_mode(state, &context.path, "response.oversharing"),
                    });
                }
            }
        }
    }

    findings
}

impl Detector for AuthDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        _headers: &HeaderMap,
    ) -> Vec<Finding> {
        match enriched.request.auth_status {
            AuthStatus::Missing => vec![Finding {
                rule_id: "auth.missing_api_key".into(),
                attack_class: AttackClass::BrokenAuthentication,
                severity: Severity::High,
                confidence: 0.99,
                message: "missing API key for protected path".into(),
                evidence: vec![FindingEvidence {
                    location: "request.headers".into(),
                    value_preview: state.config.auth.header_name.clone(),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "auth.missing_api_key"),
            }],
            AuthStatus::Invalid => vec![Finding {
                rule_id: "auth.invalid_api_key".into(),
                attack_class: AttackClass::BrokenAuthentication,
                severity: Severity::High,
                confidence: 0.99,
                message: "invalid API key for protected path".into(),
                evidence: vec![FindingEvidence {
                    location: "request.headers".into(),
                    value_preview: state.config.auth.header_name.clone(),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "auth.invalid_api_key"),
            }],
            AuthStatus::NotRequired | AuthStatus::Satisfied => Vec::new(),
        }
    }
}

impl Detector for MethodDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        _headers: &HeaderMap,
    ) -> Vec<Finding> {
        if state
            .config
            .security
            .blocked_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&enriched.request.method))
        {
            return vec![Finding {
                rule_id: "method.disallowed".into(),
                attack_class: AttackClass::MethodAbuse,
                severity: Severity::High,
                confidence: 0.98,
                message: format!("disallowed HTTP method detected: {}", enriched.request.method),
                evidence: vec![FindingEvidence {
                    location: "request.method".into(),
                    value_preview: enriched.request.method.clone(),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "method.disallowed"),
            }];
        }
        Vec::new()
    }
}

impl Detector for PathDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        _headers: &HeaderMap,
    ) -> Vec<Finding> {
        let mut candidates = vec![enriched.request.path.clone()];
        if state.config.security.inspect_query_string {
            if let Some(query) = &enriched.request.query {
                candidates.push(query.clone());
            }
        }

        inspect_payload_candidates(state, &enriched.request.path, "request.path_or_query", candidates)
    }
}

impl Detector for BodyDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        _headers: &HeaderMap,
    ) -> Vec<Finding> {
        if !state.config.security.inspect_body {
            return Vec::new();
        }

        let mut candidates = Vec::new();
        if let Some(body) = &enriched.request.body_preview {
            candidates.push(body.clone());
        }
        for field in &enriched.request.parsed_body_fields {
            candidates.push(format!("{}={}", field.key, field.value_preview));
            candidates.push(field.value_preview.clone());
        }

        inspect_payload_candidates(state, &enriched.request.path, "request.body", candidates)
    }
}

impl Detector for HeaderDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        headers: &HeaderMap,
    ) -> Vec<Finding> {
        if !state.config.security.inspect_headers {
            return Vec::new();
        }

        let mut findings = Vec::new();
        for (name, value) in headers {
            let Ok(value_str) = value.to_str() else {
                continue;
            };
            let lower = value_str.to_ascii_lowercase();

            if lower.contains('\r') || lower.contains('\n') {
                findings.push(Finding {
                    rule_id: "header.crlf".into(),
                    attack_class: AttackClass::HeaderInjection,
                    severity: Severity::Critical,
                    confidence: 0.97,
                    message: format!("CRLF/header injection markers in header {name}"),
                    evidence: vec![FindingEvidence {
                        location: format!("header.{name}"),
                        value_preview: core::truncate(value_str, 200),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "header.crlf"),
                });
            }

            if name == HeaderName::from_static("transfer-encoding")
                && lower.contains("chunked")
                && headers.contains_key("content-length")
            {
                findings.push(Finding {
                    rule_id: "smuggling.cl_te".into(),
                    attack_class: AttackClass::RequestSmuggling,
                    severity: Severity::High,
                    confidence: 0.72,
                    message: "possible CL/TE ambiguity detected".into(),
                    evidence: vec![FindingEvidence {
                        location: format!("header.{name}"),
                        value_preview: core::truncate(value_str, 200),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "smuggling.cl_te"),
                });
            }
        }

        findings
    }
}

impl Detector for JwtSecurityDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        headers: &HeaderMap,
    ) -> Vec<Finding> {
        if !state.config.jwt.enabled {
            return Vec::new();
        }

        let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
            return Vec::new();
        };
        let Some(token) = auth.strip_prefix("Bearer ") else {
            return Vec::new();
        };

        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3 {
            return vec![Finding {
                rule_id: "jwt.invalid_structure".to_string(),
                attack_class: AttackClass::JwtAbuse,
                severity: Severity::High,
                confidence: 0.95,
                message: "JWT does not have 3 segments".to_string(),
                evidence: vec![FindingEvidence {
                    location: "request.headers.authorization".to_string(),
                    value_preview: "bearer token".to_string(),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "jwt.invalid_structure"),
            }];
        }

        let Some(header) = decode_jwt_segment(parts[0]) else {
            return vec![Finding {
                rule_id: "jwt.invalid_encoding".to_string(),
                attack_class: AttackClass::JwtAbuse,
                severity: Severity::High,
                confidence: 0.96,
                message: "JWT header segment is not valid base64url JSON".to_string(),
                evidence: vec![FindingEvidence {
                    location: "jwt.header".to_string(),
                    value_preview: core::truncate(parts[0], 80),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "jwt.invalid_encoding"),
            }];
        };

        let Some(payload) = decode_jwt_segment(parts[1]) else {
            return vec![Finding {
                rule_id: "jwt.invalid_encoding".to_string(),
                attack_class: AttackClass::JwtAbuse,
                severity: Severity::High,
                confidence: 0.96,
                message: "JWT payload segment is not valid base64url JSON".to_string(),
                evidence: vec![FindingEvidence {
                    location: "jwt.payload".to_string(),
                    value_preview: core::truncate(parts[1], 80),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "jwt.invalid_encoding"),
            }];
        };

        let mut findings = Vec::new();

        if state.config.jwt.reject_alg_none {
            if header
                .get("alg")
                .and_then(|v| v.as_str())
                .map(|v| v.eq_ignore_ascii_case("none"))
                .unwrap_or(false)
            {
                findings.push(Finding {
                    rule_id: "jwt.alg_none".to_string(),
                    attack_class: AttackClass::JwtAbuse,
                    severity: Severity::Critical,
                    confidence: 0.99,
                    message: "JWT uses forbidden alg=none".to_string(),
                    evidence: vec![FindingEvidence {
                        location: "jwt.header.alg".to_string(),
                        value_preview: "none".to_string(),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "jwt.alg_none"),
                });
            }
        }

        if let Some(expected) = &state.config.jwt.expected_issuer {
            let actual = payload.get("iss").and_then(|v| v.as_str()).unwrap_or_default();
            if actual != expected {
                findings.push(Finding {
                    rule_id: "jwt.invalid_issuer".to_string(),
                    attack_class: AttackClass::JwtAbuse,
                    severity: Severity::High,
                    confidence: 0.92,
                    message: "JWT issuer does not match configured issuer".to_string(),
                    evidence: vec![FindingEvidence {
                        location: "jwt.claims.iss".to_string(),
                        value_preview: actual.to_string(),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "jwt.invalid_issuer"),
                });
            }
        }

        if let Some(expected) = &state.config.jwt.expected_audience {
            let valid = match payload.get("aud") {
                Some(serde_json::Value::String(v)) => v == expected,
                Some(serde_json::Value::Array(v)) => {
                    v.iter().any(|i| i.as_str() == Some(expected))
                }
                _ => false,
            };

            if !valid {
                findings.push(Finding {
                    rule_id: "jwt.invalid_audience".to_string(),
                    attack_class: AttackClass::JwtAbuse,
                    severity: Severity::High,
                    confidence: 0.90,
                    message: "JWT audience does not match configured audience".to_string(),
                    evidence: vec![FindingEvidence {
                        location: "jwt.claims.aud".to_string(),
                        value_preview: expected.clone(),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "jwt.invalid_audience"),
                });
            }
        }

        let required: std::collections::HashSet<_> =
            enriched.required_scopes.iter().cloned().collect();

        if !required.is_empty() {
            let scopes: std::collections::HashSet<String> = payload
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .or_else(|| {
                    payload.get("scope").and_then(|v| v.as_str()).map(|scope| {
                        scope.split_whitespace().map(|s| s.to_string()).collect()
                    })
                })
                .unwrap_or_default();

            let missing: Vec<_> = required.difference(&scopes).cloned().collect();
            if !missing.is_empty() {
                findings.push(Finding {
                    rule_id: "jwt.missing_scope".to_string(),
                    attack_class: AttackClass::JwtAbuse,
                    severity: Severity::High,
                    confidence: 0.90,
                    message: format!("JWT missing required scopes: {}", missing.join(",")),
                    evidence: vec![FindingEvidence {
                        location: "jwt.claims.scope".to_string(),
                        value_preview: missing.join(","),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "jwt.missing_scope"),
                });
            }
        }

        findings
    }
}
impl Detector for ObjectAbuseDetector {
    fn detect(
        &self,
        state: &AppState,
        enriched: &EnrichedRequestContext,
        _headers: &HeaderMap,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let distinct: HashSet<_> = enriched.object_id_candidates.iter().collect();
        if distinct.len() >= 3 {
            findings.push(Finding {
                rule_id: "object.multiple_ids".to_string(),
                attack_class: AttackClass::ObjectEnumeration,
                severity: Severity::Medium,
                confidence: 0.68,
                message: "multiple object identifiers present in one request".to_string(),
                evidence: vec![FindingEvidence {
                    location: "request.object_ids".to_string(),
                    value_preview: distinct.into_iter().cloned().collect::<Vec<_>>().join(","),
                }],
                mode: resolve_rule_mode(state, &enriched.request.path, "object.multiple_ids"),
            });
        }

        if let (Some(auth_tenant), Some(resource_tenant)) = (
            enriched.tenant_id.as_deref(),
            extract_tenant_hint(&enriched.request),
        ) {
            if auth_tenant != resource_tenant {
                findings.push(Finding {
                    rule_id: "tenant.cross_boundary".to_string(),
                    attack_class: AttackClass::TenantBoundaryViolation,
                    severity: Severity::Critical,
                    confidence: 0.94,
                    message: "possible cross-tenant resource access attempt".to_string(),
                    evidence: vec![FindingEvidence {
                        location: "request.tenant_context".to_string(),
                        value_preview: format!("auth_tenant={auth_tenant}, resource_tenant={resource_tenant}"),
                    }],
                    mode: resolve_rule_mode(state, &enriched.request.path, "tenant.cross_boundary"),
                });
            }
        }

        findings
    }
}

fn inspect_payload_candidates(
    state: &AppState,
    path: &str,
    location: &str,
    candidates: Vec<String>,
) -> Vec<Finding> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let normalized = normalized_variants(candidates);
    let haystack = normalized.join(" | ");
    let lower = haystack.to_ascii_lowercase();
    let mut findings = Vec::new();

    if lower.contains("../")
        || lower.contains("..\\")
        || lower.contains("%2e%2e")
        || lower.contains("%252e%252e")
    {
        findings.push(Finding {
            rule_id: "path.traversal.basic".into(),
            attack_class: AttackClass::PathTraversal,
            severity: Severity::High,
            confidence: 0.95,
            message: "path traversal markers detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, "path.traversal.basic"),
        });
    }

    if SQLI_RE.is_match(&lower) {
        let rule_id = if location == "request.body" {
            "body.sqli.basic"
        } else {
            "sqli.basic"
        };

        findings.push(Finding {
            rule_id: rule_id.into(),
            attack_class: AttackClass::SqlInjection,
            severity: Severity::Critical,
            confidence: 0.91,
            message: "SQL injection indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, rule_id),
        });
    }

    if XSS_RE.is_match(&lower) {
        let rule_id = if location == "request.body" {
            "body.xss.basic"
        } else {
            "xss.basic"
        };

        findings.push(Finding {
            rule_id: rule_id.into(),
            attack_class: AttackClass::Xss,
            severity: Severity::High,
            confidence: 0.89,
            message: "XSS indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, rule_id),
        });
    }

    if CMDI_RE.is_match(&lower) {
        let rule_id = if location == "request.body" {
            "body.cmdi.basic"
        } else {
            "cmdi.basic"
        };

        findings.push(Finding {
            rule_id: rule_id.into(),
            attack_class: AttackClass::CommandInjection,
            severity: Severity::Critical,
            confidence: 0.87,
            message: "command injection indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, rule_id),
        });
    }

    if SSRF_RE.is_match(&lower) {
        findings.push(Finding {
            rule_id: "ssrf.basic".into(),
            attack_class: AttackClass::Ssrf,
            severity: Severity::High,
            confidence: 0.80,
            message: "SSRF-like indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, "ssrf.basic"),
        });
    }

    let percent_count = lower.matches('%').count();
    if percent_count >= 8 || lower.contains("%25") {
        findings.push(Finding {
            rule_id: "evasion.encoding".into(),
            attack_class: AttackClass::PayloadEvasion,
            severity: Severity::Medium,
            confidence: 0.76,
            message: "encoded or evasive payload indicators detected".into(),
            evidence: vec![FindingEvidence {
                location: location.to_string(),
                value_preview: core::truncate(&haystack, 200),
            }],
            mode: resolve_rule_mode(state, path, "evasion.encoding"),
        });
    }

    findings
}

fn normalized_variants(candidates: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();

    for candidate in candidates {
        normalized.push(candidate.clone());

        if let Ok(decoded) = decode(&candidate) {
            normalized.push(decoded.to_string());

            if let Ok(double_decoded) = decode(decoded.as_ref()) {
                normalized.push(double_decoded.to_string());
            }
        }
    }

    normalized
}

fn decode_jwt_segment(segment: &str) -> Option<serde_json::Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let decoded = URL_SAFE_NO_PAD.decode(segment.as_bytes()).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn extract_tenant_hint(request: &RequestContext) -> Option<&str> {
    request
        .parsed_body_fields
        .iter()
        .find(|f| {
            let key = f.key.to_ascii_lowercase();
            key == "tenant_id" || key == "tenant" || key.ends_with("tenant_id")
        })
        .map(|f| f.value_preview.as_str())
        .or_else(|| request.path.split('/').find(|seg| seg.starts_with("tenant_")))
}

fn count_json_fields(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(items) => items.iter().map(count_json_fields).sum(),
        serde_json::Value::Object(map) => {
            map.len() + map.values().map(count_json_fields).sum::<usize>()
        }
        _ => 0,
    }
}