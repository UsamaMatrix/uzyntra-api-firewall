use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use anyhow::Result;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use crate::types::SecurityEvent;

pub fn init(log_level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(log_level).or_else(|_| EnvFilter::try_new("info"))?;

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact()
        .init();

    Ok(())
}

pub fn emit_security_event(event: &SecurityEvent, log_path: &str) {
    match serde_json::to_string(event) {
        Ok(json) => {
            info!(security_event = %json, "security event");

            if let Err(err) = append_jsonl_line(log_path, &json) {
                error!(error = %err, log_path = %log_path, "failed to persist security event");
            }
        }
        Err(err) => error!(error = %err, "failed to serialize security event"),
    }
}

pub fn read_recent_events(log_path: &str, limit: usize) -> Result<Vec<SecurityEvent>> {
    if !Path::new(log_path).exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(log_path)?;
    let mut events = Vec::new();

    for line in content.lines().rev().take(limit) {
        let event: SecurityEvent = serde_json::from_str(line)?;
        events.push(event);
    }

    Ok(events)
}

fn append_jsonl_line(log_path: &str, line: &str) -> Result<()> {
    if let Some(parent) = Path::new(log_path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;

    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}
