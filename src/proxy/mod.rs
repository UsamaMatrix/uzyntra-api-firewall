use axum::{
    body::{to_bytes, Body},
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode},
};
use tracing::{error, info};

use crate::{
    detection, policy, rate_limit, storage, telemetry,
    mitigation,
    types::{
        AppState, AttackClass, Finding, FindingEvidence, RequestContext, SecurityEvent, Severity,
    },
};

pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response<Body> {
    let Some(context) = request.extensions().get::<RequestContext>().cloned() else {
        return response_with_status(StatusCode::INTERNAL_SERVER_ERROR, "request context missing");
    };

    let method = request.method().clone();
    let query = request.uri().query().map(ToOwned::to_owned);
    let headers = request.headers().clone();

    let mut request_findings = detection::inspect_request(&state, &context, &headers);
request_findings.extend(rate_limit::evaluate_request_with_headers(
    &state,
    &context,
    &headers,
));

    let principal_key = crate::core::derive_principal(&state, &context, &headers)
        .as_rate_limit_key();
    let trusted_source = crate::core::is_source_allowlisted(&state, &context.source_ip.to_string())
        || crate::core::is_source_allowlisted_for_path(&state, &context.source_ip.to_string(), &context.path);
    let trusted_principal = crate::core::is_principal_allowlisted(&state, &principal_key)
        || crate::core::is_principal_allowlisted_for_path(&state, &principal_key, &context.path);

    let trusted_tri_scoped = crate::core::is_tri_scoped_allowlisted(
        &state,
        &context.source_ip.to_string(),
        &principal_key,
        &context.path,
    );
    let trusted_source = trusted_source || trusted_tri_scoped;
    let trusted_principal = trusted_principal || trusted_tri_scoped;

    if trusted_source || trusted_principal {
        tracing::info!(
            request_id = %context.request_id,
            source_ip = %context.source_ip,
            principal = %principal_key,
            trusted_source,
            trusted_principal,
            "request matched allowlist; bypassing enforcement"
        );
    }

    let shadow_routes = crate::core::discover_shadow_apis(&state);
    if shadow_routes
        .iter()
        .any(|r| r.method.eq_ignore_ascii_case(&context.method) && r.normalized_path
    == crate::core::normalize_runtime_path(&crate::core::canonical_security_path(&context.path)))
    {
        request_findings.push(Finding {
            rule_id: "shadow.route_live".to_string(),
            attack_class: AttackClass::ShadowApi,
            severity: Severity::Medium,
            confidence: 0.80,
            message: "request matched a learned live route that is outside the configured spec".to_string(),
            evidence: vec![FindingEvidence {
                location: "request.path".to_string(),
                value_preview: context.path.clone(),
            }],
            mode: crate::types::resolve_rule_mode(&state, &context.path, "shadow.route_live"),
        });
    }

    let request_findings = if trusted_source || trusted_principal {
        Vec::new()
    } else {
        crate::core::filter_suppressed_findings(&state, &context.path, request_findings)
    };

    if !request_findings.is_empty() {
        let decision = policy::evaluate_findings(&state, &context, request_findings.clone());

        let event = SecurityEvent {
            request_id: context.request_id.clone(),
            timestamp: context.timestamp,
            source_ip: context.source_ip.to_string(),
            method: context.method.clone(),
            path: context.path.clone(),
            findings: request_findings,
            decision: decision.clone(),
        };

        telemetry::emit_security_event(&event, &state.config.telemetry.security_event_log_path);

        if let Err(err) = storage::persist_security_event(&state.config.storage.sqlite_path, &event) {
            error!(error = %err, "failed to persist request-side security event to SQLite");
        }

        state.telemetry_delivery.enqueue(&event);

        match &decision.outcome {
            crate::types::DecisionOutcome::Reject { .. } => {
                return mitigation::finalize_blocking_decision(&state, &context, decision);
            }
            crate::types::DecisionOutcome::Allow => {
                mitigation::apply_non_blocking_effects(&state, &context, &decision);
            }
        }
    }

    let full_url = build_upstream_url(
        &state.config.proxy.upstream_base_url,
        &path,
        query.as_deref(),
    );

    let body_bytes = match to_bytes(request.into_body(), state.config.proxy.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to read request body for proxying");
            return response_with_status(StatusCode::BAD_REQUEST, "failed to read request body");
        }
    };

    let reqwest_method = match to_reqwest_method(&method) {
        Ok(m) => m,
        Err(err) => {
            error!(error = %err, method = %method, "unsupported method for reqwest");
            return response_with_status(StatusCode::METHOD_NOT_ALLOWED, "unsupported HTTP method");
        }
    };

    let mut builder = state.proxy_client.request(reqwest_method, &full_url);

    for (name, value) in &headers {
        if should_skip_request_header(name.as_str()) {
            continue;
        }

        if let Ok(value_str) = value.to_str() {
            builder = builder.header(name.as_str(), value_str);
        }
    }

    builder = builder.body(body_bytes);

    let upstream_response = match builder.send().await {
        Ok(resp) => resp,
        Err(err) => {
            error!(
                error = %err,
                upstream = %full_url,
                "upstream proxy request failed"
            );
            return response_with_status(StatusCode::BAD_GATEWAY, "upstream request failed");
        }
    };

    let status = upstream_response.status();
    let response_headers = upstream_response.headers().clone();

    let response_body = match upstream_response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            error!(error = %err, "failed to read upstream response body");
            return response_with_status(StatusCode::BAD_GATEWAY, "failed to read upstream response");
        }
    };

    let preview_len = state
        .config
        .security
        .max_inspection_body_bytes
        .min(response_body.len());
    let response_body_preview = String::from_utf8_lossy(&response_body[..preview_len]).to_string();

    let mut response_findings =
        inspect_response_headers(&response_headers, &state, Some(&context));

    response_findings.extend(detection::inspect_response(
        &state,
        &context,
        &response_headers,
        &response_body_preview,
    ));

    let normalized_path = crate::core::normalize_runtime_path(
        &crate::core::canonical_security_path(&context.path)
    );

    if let Some(contract) = crate::core::response_contract_for_route(
        &state,
        &context.method,
        &normalized_path,
    ) {
        let status_ok = status.as_u16() == contract.expected_status;

        let content_type_value = response_headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let content_type_ok = content_type_value.starts_with(&contract.expected_content_type_prefix);

        let missing_required_headers: Vec<String> = contract
            .required_headers
            .iter()
            .filter(|header_name| !response_headers.contains_key(header_name.as_str()))
            .cloned()
            .collect();

        if !status_ok || !content_type_ok || !missing_required_headers.is_empty() {
            response_findings.push(crate::types::Finding {
                rule_id: "response.contract_mismatch".to_string(),
                attack_class: crate::types::AttackClass::ResponseLeak,
                severity: crate::types::Severity::Medium,
                confidence: 0.88,
                message: format!(
                    "response contract mismatch for {} {}",
                    context.method, normalized_path
                ),
                evidence: vec![
                    crate::types::FindingEvidence {
                        location: "response.contract.status".to_string(),
                        value_preview: format!(
                            "expected={}, actual={}",
                            contract.expected_status,
                            status.as_u16()
                        ),
                    },
                    crate::types::FindingEvidence {
                        location: "response.contract.content_type".to_string(),
                        value_preview: format!(
                            "expected_prefix={}, actual={}",
                            contract.expected_content_type_prefix,
                            content_type_value
                        ),
                    },
                    crate::types::FindingEvidence {
                        location: "response.contract.missing_headers".to_string(),
                        value_preview: missing_required_headers.join(","),
                    },
                ],
                mode: crate::types::resolve_rule_mode(
                    &state,
                    &context.path,
                    "response.contract_mismatch",
                ),
            });
        }
    }

    let response_findings = if trusted_source || trusted_principal {
        Vec::new()
    } else {
        crate::core::filter_suppressed_findings(&state, &context.path, response_findings)
    };

    if !response_findings.is_empty() {
        let decision = policy::evaluate_findings(&state, &context, response_findings.clone());
        let event = SecurityEvent {
            request_id: context.request_id.clone(),
            timestamp: context.timestamp,
            source_ip: context.source_ip.to_string(),
            method: context.method.clone(),
            path: context.path.clone(),
            findings: response_findings,
            decision: decision.clone(),
        };

        telemetry::emit_security_event(&event, &state.config.telemetry.security_event_log_path);

        if let Err(err) = storage::persist_security_event(&state.config.storage.sqlite_path, &event) {
            error!(error = %err, "failed to persist response-side security event to SQLite");
        }

        state.telemetry_delivery.enqueue(&event);

        match &decision.outcome {
            crate::types::DecisionOutcome::Reject { .. } => {
                return mitigation::finalize_blocking_decision(&state, &context, decision);
            }
            crate::types::DecisionOutcome::Allow => {
                mitigation::apply_non_blocking_effects(&state, &context, &decision);
            }
        }
    }

    let mut response = Response::new(Body::from(response_body));
    *response.status_mut() = status;

    for (name, value) in &response_headers {
        if should_skip_response_header(name.as_str()) {
            continue;
        }

        response.headers_mut().insert(name.clone(), value.clone());
    }

    if let Ok(header_name) = HeaderName::from_lowercase(b"x-firewall-proxied") {
        response
            .headers_mut()
            .insert(header_name, HeaderValue::from_static("true"));
    }

    if let Ok(value) = HeaderValue::from_str(&context.request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    info!(
        request_id = %context.request_id,
        method = %method,
        upstream = %full_url,
        status = %status,
        "request proxied successfully"
    );

    response
}

fn inspect_response_headers(
    headers: &HeaderMap,
    state: &AppState,
    context: Option<&RequestContext>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let required = [
        ("x-content-type-options", "missing.x_content_type_options"),
        ("x-frame-options", "missing.x_frame_options"),
        ("content-security-policy", "missing.csp"),
    ];

    for (header, rule_id) in required {
        if !headers.contains_key(header) {
            let path = context.map(|c| c.path.as_str()).unwrap_or("/proxy");

            findings.push(Finding {
                rule_id: rule_id.to_string(),
                attack_class: AttackClass::MissingSecurityHeaders,
                severity: Severity::Low,
                confidence: 0.95,
                message: format!("upstream response missing security header '{}'", header),
                evidence: vec![FindingEvidence {
                    location: "response.headers".into(),
                    value_preview: header.to_string(),
                }],
                mode: crate::types::resolve_rule_mode(state, path, rule_id),
            });
        }
    }

    findings
}

fn build_upstream_url(base: &str, path: &str, query: Option<&str>) -> String {
    let base = base.trim_end_matches('/');
    let path = path.trim_start_matches('/');

    match query {
        Some(q) if !q.is_empty() => format!("{base}/{path}?{q}"),
        _ => format!("{base}/{path}"),
    }
}

fn to_reqwest_method(method: &Method) -> Result<reqwest::Method, String> {
    reqwest::Method::from_bytes(method.as_str().as_bytes())
        .map_err(|err| format!("invalid reqwest method conversion: {err}"))
}

fn should_skip_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "connection" | "content-length" | "transfer-encoding"
    )
}

fn should_skip_response_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "transfer-encoding"
    )
}

fn response_with_status(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(message.to_string()));
    *response.status_mut() = status;
    response
}
