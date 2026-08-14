use std::net::SocketAddr;

use anyhow::Context;
use api_firewall::{app, config::AppConfig, enrollment, storage, telemetry};
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut config = AppConfig::load().context("failed to load application config")?;
    telemetry::init(&config.telemetry.log_level)?;

    enrollment::enroll_control_plane_if_configured(&mut config.control_plane)
        .await
        .context("failed to enroll with control plane")?;

    storage::init_db(&config.storage.sqlite_path).context("failed to initialize SQLite storage")?;

    let public_bind_addr: SocketAddr =
        config.server.public_bind_addr.parse().with_context(|| {
            format!(
                "invalid public bind address: {}",
                config.server.public_bind_addr
            )
        })?;

    let admin_bind_addr: SocketAddr = config.server.admin_bind_addr.parse().with_context(|| {
        format!(
            "invalid admin bind address: {}",
            config.server.admin_bind_addr
        )
    })?;

    let app_state = app::build_state(config.clone())?;
    app::hydrate_state_from_storage(&app_state)?;
    app::start_background_tasks(app_state.clone());

    let public_router = app::build_public_router(app_state.clone());
    let admin_router = app::build_admin_router(app_state);

    let public_listener = TcpListener::bind(public_bind_addr)
        .await
        .with_context(|| format!("failed to bind public listener {}", public_bind_addr))?;

    let admin_listener = TcpListener::bind(admin_bind_addr)
        .await
        .with_context(|| format!("failed to bind admin listener {}", admin_bind_addr))?;

    info!(
        public_bind_addr = %public_bind_addr,
        admin_bind_addr = %admin_bind_addr,
        upstream = %config.proxy.upstream_base_url,
        sqlite_path = %config.storage.sqlite_path,
        "api firewall starting"
    );

    let public_server = axum::serve(
        public_listener,
        public_router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    let admin_server = axum::serve(
        admin_listener,
        admin_router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    tokio::try_join!(public_server, admin_server)
        .context("one of the listeners exited with error")?;

    Ok(())
}
