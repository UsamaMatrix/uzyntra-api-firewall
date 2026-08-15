use std::{
    net::IpAddr,
    str::FromStr,
    time::{Duration, Instant},
};

use api_firewall::{
    detection::normalization::{normalize_request, NormalizationLimits},
    types::{AuthStatus, ParsedBodyField, RequestContext},
};
use axum::http::HeaderMap;

fn main() {
    let headers = HeaderMap::new();
    let context = RequestContext {
        request_id: "bench-request".to_string(),
        timestamp: chrono::Utc::now(),
        source_ip: IpAddr::from_str("203.0.113.10").unwrap(),
        method: "POST".to_string(),
        path: "/api/orders/%257B123%257D/items".to_string(),
        query: Some(
            "q=%2527%2520or%25201%253D1&redirect=http%3A%2F%2F169.254.169.254%2Flatest".to_string(),
        ),
        body_preview: Some(
            r#"{"customerId":"cust_123","notes":"<script>alert(1)</script>"}"#.to_string(),
        ),
        parsed_body_fields: vec![ParsedBodyField {
            key: "notes".to_string(),
            value_preview: "<script>alert(1)</script>".to_string(),
        }],
        auth_status: AuthStatus::Satisfied,
    };
    let limits = NormalizationLimits {
        max_bytes: 16 * 1024,
        max_decode_passes: 2,
        max_query_params: 100,
    };

    let iterations = 20_000;
    let mut samples = Vec::with_capacity(iterations);
    let started = Instant::now();
    for _ in 0..iterations {
        let op_started = Instant::now();
        let normalized = normalize_request(&context, &headers, limits.clone());
        std::hint::black_box(normalized);
        samples.push(op_started.elapsed());
    }
    let elapsed = started.elapsed();
    let per_second = iterations as f64 / elapsed.as_secs_f64();
    samples.sort_unstable();

    println!(
        "phase5_detection_hot_path iterations={} elapsed_ms={} requests_per_second={:.2} p50_ns={} p95_ns={} p99_ns={}",
        iterations,
        elapsed.as_millis(),
        per_second,
        percentile_ns(&samples, 0.50),
        percentile_ns(&samples, 0.95),
        percentile_ns(&samples, 0.99)
    );
}

fn percentile_ns(samples: &[Duration], percentile: f64) -> u128 {
    if samples.is_empty() {
        return 0;
    }

    let rank = ((samples.len() - 1) as f64 * percentile).round() as usize;
    samples[rank].as_nanos()
}
