use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::RwLock,
};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::DiscoveryConfig,
    detection::normalization::is_sensitive_key,
    types::{AttackClass, Finding, FindingEvidence, Severity},
};

static SCHEMA_MEMORY: Lazy<RwLock<HashMap<String, LearnedJsonSchema>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearnedJsonSchema {
    pub route_key: String,
    pub samples: u64,
    pub fields: BTreeMap<String, LearnedField>,
    pub max_depth_seen: usize,
    pub max_array_len_seen: usize,
    pub max_body_bytes_seen: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearnedField {
    pub seen: u64,
    pub types: BTreeMap<String, u64>,
    pub sensitive: bool,
}

pub fn clear_schema_memory() -> usize {
    let mut guard = SCHEMA_MEMORY.write().expect("schema memory poisoned");
    let count = guard.len();
    guard.clear();
    count
}

pub fn snapshot_schema_memory(limit: usize) -> Vec<LearnedJsonSchema> {
    let guard = SCHEMA_MEMORY.read().expect("schema memory poisoned");
    let mut items: Vec<_> = guard.values().cloned().collect();
    items.sort_by(|a, b| b.samples.cmp(&a.samples));
    items.into_iter().take(limit).collect()
}

pub fn learn_and_detect_json_schema(
    route_key: &str,
    body: Option<&str>,
    content_type: Option<&str>,
    config: &DiscoveryConfig,
    mode: crate::config::RuleMode,
) -> Vec<Finding> {
    let Some(body) = body.filter(|value| !value.trim().is_empty()) else {
        return Vec::new();
    };

    if !content_type
        .map(|value| value.contains("application/json"))
        .unwrap_or(false)
    {
        return unexpected_content_type(route_key, content_type, mode);
    }

    let parsed = match serde_json::from_str::<Value>(body) {
        Ok(value) => value,
        Err(_) => {
            return vec![schema_finding(
                "UZ-API-SCHEMA-004",
                Severity::Medium,
                0.88,
                "malformed JSON request body",
                "request.body",
                "invalid_json",
                mode,
            )]
        }
    };

    let depth = json_depth(&parsed);
    let max_array_len = max_array_len(&parsed);
    let field_map = flatten_json_fields(&parsed, config.max_schema_fields);
    let mut findings = Vec::new();

    if depth > config.max_json_depth {
        findings.push(schema_finding(
            "UZ-API-SCHEMA-005",
            Severity::High,
            0.90,
            "JSON request body exceeds maximum inspection depth",
            "request.body.depth",
            &format!("depth={depth}, max={}", config.max_json_depth),
            mode.clone(),
        ));
    }

    if max_array_len > config.max_json_array_len {
        findings.push(schema_finding(
            "UZ-API-SCHEMA-006",
            Severity::Medium,
            0.86,
            "JSON request body contains an unusually large array",
            "request.body.array",
            &format!(
                "array_len={max_array_len}, max={}",
                config.max_json_array_len
            ),
            mode.clone(),
        ));
    }

    let mut guard = SCHEMA_MEMORY.write().expect("schema memory poisoned");
    if !guard.contains_key(route_key) && guard.len() >= config.max_schema_routes {
        evict_lowest_sample_schema(&mut guard);
    }

    let schema = guard
        .entry(route_key.to_string())
        .or_insert_with(|| LearnedJsonSchema {
            route_key: route_key.to_string(),
            ..Default::default()
        });

    if schema.samples >= config.schema_min_samples {
        let learned_fields: HashSet<_> = schema.fields.keys().cloned().collect();
        for (field, kind) in &field_map {
            if !learned_fields.contains(field) && !is_sensitive_key(field) {
                findings.push(schema_finding(
                    "UZ-API-SCHEMA-001",
                    Severity::Medium,
                    0.72,
                    "unexpected JSON request field observed",
                    &format!("body.{field}"),
                    field,
                    mode.clone(),
                ));
            } else if let Some(learned) = schema.fields.get(field) {
                let expected = dominant_type(learned);
                if expected.as_deref() != Some(kind.as_str()) && !learned.sensitive {
                    findings.push(schema_finding(
                        "UZ-API-SCHEMA-003",
                        Severity::Medium,
                        0.78,
                        "JSON request field type differs from learned schema",
                        &format!("body.{field}"),
                        &format!("field={field}, expected={expected:?}, actual={kind}"),
                        mode.clone(),
                    ));
                }
            }
        }

        for (field, learned) in &schema.fields {
            let requiredness = learned.seen as f64 / schema.samples.max(1) as f64;
            if requiredness >= 0.90 && !field_map.contains_key(field) && !learned.sensitive {
                findings.push(schema_finding(
                    "UZ-API-SCHEMA-002",
                    Severity::Low,
                    0.68,
                    "usually-present JSON request field is missing",
                    &format!("body.{field}"),
                    field,
                    mode.clone(),
                ));
            }
        }

        let body_len = body.len();
        if schema.max_body_bytes_seen > 0 && body_len > schema.max_body_bytes_seen.saturating_mul(4)
        {
            findings.push(schema_finding(
                "UZ-API-SCHEMA-007",
                Severity::Medium,
                0.75,
                "request body is unusually large for learned route",
                "request.body.size",
                &format!(
                    "bytes={body_len}, learned_max={}",
                    schema.max_body_bytes_seen
                ),
                mode.clone(),
            ));
        }
    }

    schema.samples = schema.samples.saturating_add(1);
    schema.max_depth_seen = schema.max_depth_seen.max(depth);
    schema.max_array_len_seen = schema.max_array_len_seen.max(max_array_len);
    schema.max_body_bytes_seen = schema.max_body_bytes_seen.max(body.len());

    for (field, kind) in field_map {
        let entry = schema
            .fields
            .entry(field.clone())
            .or_insert_with(|| LearnedField {
                sensitive: is_sensitive_key(&field),
                ..Default::default()
            });
        entry.seen = entry.seen.saturating_add(1);
        *entry.types.entry(kind).or_insert(0) += 1;
    }

    findings
}

fn unexpected_content_type(
    route_key: &str,
    content_type: Option<&str>,
    mode: crate::config::RuleMode,
) -> Vec<Finding> {
    let Some(content_type) = content_type else {
        return Vec::new();
    };

    if content_type.contains("application/json") {
        return Vec::new();
    }

    vec![schema_finding(
        "UZ-API-SCHEMA-008",
        Severity::Low,
        0.62,
        "request content type is not JSON for schema learning",
        "request.content_type",
        &format!("route={route_key}, content_type={content_type}"),
        mode,
    )]
}

fn schema_finding(
    rule_id: &str,
    severity: Severity,
    confidence: f32,
    message: &str,
    location: &str,
    value_preview: &str,
    mode: crate::config::RuleMode,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        attack_class: AttackClass::SchemaViolation,
        severity,
        confidence,
        message: message.to_string(),
        evidence: vec![FindingEvidence {
            location: location.to_string(),
            value_preview: crate::core::truncate(value_preview, 160),
        }],
        mode,
    }
}

fn flatten_json_fields(value: &Value, max_fields: usize) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    flatten_json_fields_inner(value, "", max_fields, &mut out);
    out
}

fn flatten_json_fields_inner(
    value: &Value,
    prefix: &str,
    max_fields: usize,
    out: &mut BTreeMap<String, String>,
) {
    if out.len() >= max_fields {
        return;
    }

    if let Value::Object(map) = value {
        for (key, child) in map {
            if out.len() >= max_fields {
                break;
            }
            let clean_key = key
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
                .to_ascii_lowercase();
            if clean_key.is_empty() {
                continue;
            }
            let path = if prefix.is_empty() {
                clean_key
            } else {
                format!("{prefix}.{clean_key}")
            };
            out.insert(path.clone(), json_kind(child).to_string());
            if child.is_object() {
                flatten_json_fields_inner(child, &path, max_fields, out);
            }
        }
    }
}

fn dominant_type(field: &LearnedField) -> Option<String> {
    field
        .types
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(kind, _)| kind.clone())
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(json_depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 1,
    }
}

fn max_array_len(value: &Value) -> usize {
    match value {
        Value::Array(items) => items
            .len()
            .max(items.iter().map(max_array_len).max().unwrap_or(0)),
        Value::Object(map) => map.values().map(max_array_len).max().unwrap_or(0),
        _ => 0,
    }
}

fn evict_lowest_sample_schema(map: &mut HashMap<String, LearnedJsonSchema>) {
    let victim = map
        .iter()
        .min_by_key(|(_, schema)| schema.samples)
        .map(|(key, _)| key.clone());
    if let Some(key) = victim {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_learning_redacts_sensitive_and_flags_unexpected_fields_after_warmup() {
        clear_schema_memory();
        let config = DiscoveryConfig {
            enabled: true,
            schema_min_samples: 2,
            ..Default::default()
        };
        let mode = crate::config::RuleMode::DetectOnly;

        assert!(learn_and_detect_json_schema(
            "POST:/login",
            Some(r#"{"email":"a@example.com","password":"secret"}"#),
            Some("application/json"),
            &config,
            mode.clone(),
        )
        .is_empty());

        assert!(learn_and_detect_json_schema(
            "POST:/login",
            Some(r#"{"email":"b@example.com","password":"secret"}"#),
            Some("application/json"),
            &config,
            mode.clone(),
        )
        .is_empty());

        let findings = learn_and_detect_json_schema(
            "POST:/login",
            Some(r#"{"email":"c@example.com","password":"secret","admin":true}"#),
            Some("application/json"),
            &config,
            mode,
        );

        assert!(findings
            .iter()
            .any(|finding| finding.rule_id == "UZ-API-SCHEMA-001"));
        assert!(!format!("{:?}", snapshot_schema_memory(10)).contains("secret"));
    }
}
