use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::ControlPlaneConfig;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentRequest<'a> {
    enrollment_token: &'a str,
    installation_identifier: Option<&'a str>,
    hostname: Option<&'a str>,
    version: Option<&'a str>,
    region: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentResponse {
    success: bool,
    data: Option<EnrollmentData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentData {
    firewall: EnrolledFirewall,
    plaintext_api_key: String,
}

#[derive(Debug, Deserialize)]
struct EnrolledFirewall {
    id: String,
}

pub async fn enroll_control_plane_if_configured(config: &mut ControlPlaneConfig) -> Result<()> {
    if !config.enrollment_enabled {
        return Ok(());
    }

    let client = Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms.max(1)))
        .user_agent("uzyntra-firewall-enrollment/0.1.0")
        .build()
        .context("failed to build control-plane enrollment HTTP client")?;

    let request = EnrollmentRequest {
        enrollment_token: config.enrollment_token.trim(),
        installation_identifier: optional_trimmed(&config.installation_identifier),
        hostname: optional_trimmed(&config.hostname),
        version: optional_trimmed(&config.version),
        region: optional_trimmed(&config.region),
    };

    let response = client
        .post(config.enrollment_url.trim())
        .json(&request)
        .send()
        .await
        .context("control-plane enrollment request failed")?;

    if !response.status().is_success() {
        bail!(
            "control-plane enrollment failed with status {}",
            response.status()
        );
    }

    let response: EnrollmentResponse = response
        .json()
        .await
        .context("failed to parse control-plane enrollment response")?;

    let Some(data) = response.data else {
        bail!("control-plane enrollment response missing data");
    };

    if !response.success
        || data.firewall.id.trim().is_empty()
        || data.plaintext_api_key.trim().is_empty()
    {
        bail!("control-plane enrollment response is invalid");
    }

    config.telemetry_enabled = true;
    config.firewall_instance_id = data.firewall.id;
    config.api_key = data.plaintext_api_key;
    config.enrollment_token.clear();

    info!("control-plane enrollment completed");
    Ok(())
}

fn optional_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::optional_trimmed;

    #[test]
    fn optional_trimmed_rejects_blank_values() {
        assert_eq!(optional_trimmed("  "), None);
        assert_eq!(optional_trimmed("edge-1"), Some("edge-1"));
    }
}
