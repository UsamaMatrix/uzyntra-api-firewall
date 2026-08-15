use axum::http::HeaderMap;
use urlencoding::decode;

use crate::types::RequestContext;

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "api_key",
    "apikey",
    "session",
    "cookie",
    "card",
];

#[derive(Debug, Clone)]
pub struct NormalizationLimits {
    pub max_bytes: usize,
    pub max_decode_passes: usize,
    pub max_query_params: usize,
}

#[derive(Debug, Clone)]
pub struct NormalizedRequest {
    pub method: String,
    pub path: String,
    pub query_pairs: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body_variants: Vec<String>,
    pub inspection_values: Vec<(String, String)>,
    pub query_param_count: usize,
}

pub fn normalize_request(
    request: &RequestContext,
    headers: &HeaderMap,
    limits: NormalizationLimits,
) -> NormalizedRequest {
    let path = bounded_decode(&request.path, &limits).to_ascii_lowercase();
    let query_param_count = count_query_params(request.query.as_deref(), limits.max_query_params);
    let query_pairs = normalize_query(request.query.as_deref(), &limits);
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        })
        .filter(|value| !value.is_empty());

    let mut body_variants = Vec::new();
    if let Some(body) = &request.body_preview {
        let decoded = bounded_decode(body, &limits);
        body_variants.push(redact_sensitive_text(&bounded(body, limits.max_bytes)));
        if decoded != *body {
            body_variants.push(redact_sensitive_text(&decoded));
        }
    }

    let mut inspection_values = Vec::new();
    inspection_values.push(("request.path".to_string(), path.clone()));

    for (key, value) in &query_pairs {
        inspection_values.push((format!("query.{key}"), value.clone()));
    }

    for field in &request.parsed_body_fields {
        let key = bounded_decode(&field.key, &limits).to_ascii_lowercase();
        let value = if is_sensitive_key(&key) {
            "[redacted]".to_string()
        } else {
            bounded_decode(&field.value_preview, &limits)
        };
        inspection_values.push((format!("body.{key}"), value));
    }

    for value in &body_variants {
        inspection_values.push(("request.body".to_string(), value.clone()));
    }

    NormalizedRequest {
        method: request.method.to_ascii_uppercase(),
        path,
        query_param_count,
        query_pairs,
        content_type,
        body_variants,
        inspection_values,
    }
}

pub fn bounded_decode(input: &str, limits: &NormalizationLimits) -> String {
    let mut current = bounded(input, limits.max_bytes);

    for _ in 0..limits.max_decode_passes.min(4) {
        let Ok(decoded) = decode(&current) else {
            break;
        };
        let decoded = bounded(decoded.as_ref(), limits.max_bytes);
        if decoded == current {
            break;
        }
        current = decoded;
    }

    current
}

pub fn redact_sensitive_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len().min(4096));
    for pair in value.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let val = parts.next();
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(key);
        if let Some(val) = val {
            out.push('=');
            if is_sensitive_key(&key.to_ascii_lowercase()) {
                out.push_str("[redacted]");
            } else {
                out.push_str(val);
            }
        }
    }
    out
}

pub fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .to_ascii_lowercase();

    SENSITIVE_KEYS
        .iter()
        .any(|needle| normalized.contains(needle))
}

fn normalize_query(raw: Option<&str>, limits: &NormalizationLimits) -> Vec<(String, String)> {
    let Some(raw) = raw else {
        return Vec::new();
    };

    raw.split('&')
        .take(limits.max_query_params)
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let key = bounded_decode(key, limits).to_ascii_lowercase();
            if key.is_empty() {
                return None;
            }
            let raw_value = parts.next().unwrap_or_default();
            let value = if is_sensitive_key(&key) {
                "[redacted]".to_string()
            } else {
                bounded_decode(raw_value, limits)
            };
            Some((key, value))
        })
        .collect()
}

fn count_query_params(raw: Option<&str>, max_query_params: usize) -> usize {
    let Some(raw) = raw else {
        return 0;
    };

    raw.split('&')
        .filter(|pair| !pair.is_empty())
        .take(max_query_params.saturating_add(1))
        .count()
}

fn bounded(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn bounded_decode_handles_double_encoding_without_loops() {
        let limits = NormalizationLimits {
            max_bytes: 128,
            max_decode_passes: 2,
            max_query_params: 20,
        };

        assert_eq!(bounded_decode("%252e%252e%252fetc", &limits), "../etc");
    }

    #[test]
    fn query_normalization_redacts_sensitive_values() {
        let request = RequestContext {
            request_id: "r".to_string(),
            timestamp: Utc::now(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: "GET".to_string(),
            path: "/users/123".to_string(),
            query: Some("token=abc&id=42".to_string()),
            body_preview: None,
            parsed_body_fields: Vec::new(),
            auth_status: crate::types::AuthStatus::NotRequired,
        };

        let normalized = normalize_request(
            &request,
            &HeaderMap::new(),
            NormalizationLimits {
                max_bytes: 128,
                max_decode_passes: 2,
                max_query_params: 20,
            },
        );

        assert!(normalized
            .inspection_values
            .iter()
            .any(|(_, value)| value == "[redacted]"));
        assert!(!format!("{:?}", normalized.inspection_values).contains("abc"));
    }

    #[test]
    fn query_param_count_reports_over_limit_fanout() {
        let request = RequestContext {
            request_id: "r".to_string(),
            timestamp: Utc::now(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: Some(
                (0..5)
                    .map(|i| format!("p{i}=1"))
                    .collect::<Vec<_>>()
                    .join("&"),
            ),
            body_preview: None,
            parsed_body_fields: Vec::new(),
            auth_status: crate::types::AuthStatus::NotRequired,
        };

        let normalized = normalize_request(
            &request,
            &HeaderMap::new(),
            NormalizationLimits {
                max_bytes: 128,
                max_decode_passes: 2,
                max_query_params: 3,
            },
        );

        assert_eq!(normalized.query_pairs.len(), 3);
        assert_eq!(normalized.query_param_count, 4);
    }

    #[test]
    fn query_param_count_ignores_empty_query_fragments() {
        let request = RequestContext {
            request_id: "r".to_string(),
            timestamp: Utc::now(),
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: Some("&a=1&&b=2&".to_string()),
            body_preview: None,
            parsed_body_fields: Vec::new(),
            auth_status: crate::types::AuthStatus::NotRequired,
        };

        let normalized = normalize_request(
            &request,
            &HeaderMap::new(),
            NormalizationLimits {
                max_bytes: 128,
                max_decode_passes: 2,
                max_query_params: 10,
            },
        );

        assert_eq!(normalized.query_param_count, 2);
    }
}
