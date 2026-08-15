use anyhow::Context;
use axum::{
    middleware,
    routing::{any, get, post},
    Router,
};
use reqwest::Client;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::{
    config::AppConfig,
    control_plane, core,
    mitigation::TemporaryMitigationStore,
    proxy,
    rate_limit::RateLimiter,
    storage,
    telemetry_delivery::TelemetryDelivery,
    types::{AppState, LivePolicyState},
};

pub fn build_state(config: AppConfig) -> anyhow::Result<AppState> {
    let proxy_client = Client::builder()
        .user_agent("api-firewall/0.1.0")
        .pool_idle_timeout(std::time::Duration::from_secs(
            config.proxy.pool_idle_timeout_secs,
        ))
        .connect_timeout(std::time::Duration::from_secs(
            config.proxy.connect_timeout_secs,
        ))
        .timeout(std::time::Duration::from_secs(
            config.proxy.request_timeout_secs,
        ))
        .build()
        .context("failed to build reqwest client")?;

    let (telemetry_delivery, telemetry_worker) = TelemetryDelivery::new(&config.control_plane)?;

    let state = AppState {
        config: std::sync::Arc::new(config.clone()),
        proxy_client,
        rate_limiter: std::sync::Arc::new(RateLimiter::new(
            config.security.rate_limit.requests_per_window,
            config.security.rate_limit.window_secs,
        )),
        mitigation_store: std::sync::Arc::new(TemporaryMitigationStore::default()),
        policy_state: std::sync::Arc::new(std::sync::RwLock::new(LivePolicyState::from_config(
            &config,
        ))),
        telemetry_delivery,
        started_at: chrono::Utc::now(),
    };

    if config.control_plane.telemetry_enabled {
        tokio::spawn(telemetry_worker.run());
    }

    info!("application state initialized");
    Ok(state)
}

pub fn hydrate_state_from_storage(state: &AppState) -> anyhow::Result<()> {
    let mitigations = storage::load_active_mitigations(&state.config.storage.sqlite_path)?;
    let reputations = storage::load_reputations(&state.config.storage.sqlite_path)?;
    let learned_routes = storage::load_learned_routes(&state.config.storage.sqlite_path)?;

    for mitigation in mitigations {
        if mitigation.expires_at > chrono::Utc::now() {
            state.mitigation_store.insert_block_hydrated(mitigation);
        }
    }

    for reputation in reputations {
        state
            .mitigation_store
            .insert_reputation_hydrated(reputation);
    }

    core::restore_learned_routes(&learned_routes);

    info!(
        active_blocks = state.mitigation_store.active_block_count(),
        reputation_entries = state.mitigation_store.list_reputations().len(),
        learned_routes = learned_routes.len(),
        "hydrated in-memory state from SQLite"
    );

    Ok(())
}

pub fn start_background_tasks(state: AppState) {
    tokio::spawn(async move {
        let interval_secs = 30u64;

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            let expired = state.mitigation_store.cleanup_expired();

            if !expired.is_empty() {
                for ip in &expired {
                    if let Err(err) = storage::delete_active_mitigation(
                        &state.config.storage.sqlite_path,
                        &ip.to_string(),
                    ) {
                        tracing::error!(error = %err, source_ip = %ip, "failed to delete expired mitigation from SQLite");
                    }
                }

                info!(
                    removed = expired.len(),
                    "cleaned up expired temporary mitigations"
                );
            }
        }
    });
}

pub fn build_public_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(control_plane::root))
        .route("/healthz", get(control_plane::public_healthz))
        .route("/readyz", get(control_plane::readyz))
        .route("/proxy/{*path}", any(proxy::proxy_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::security_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            core::request_context_middleware,
        ))
        .with_state(state)
}

pub fn build_admin_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            "http://localhost:3000"
                .parse::<axum::http::HeaderValue>()
                .unwrap(),
        )
        .allow_methods(Any)
        .allow_headers(Any);

    let live_router = if state.config.server.admin_public_health_enabled {
        Router::new().route("/livez", get(control_plane::admin_livez))
    } else {
        Router::new()
    };

    live_router
        .merge(
            Router::new()
                .route("/healthz", get(control_plane::admin_healthz))
                .route("/v1/admin/config", get(control_plane::get_config))
                .route(
                    "/v1/admin/policy/effective",
                    get(control_plane::effective_policy),
                )
                .route(
                    "/v1/admin/policy/rules/set",
                    post(control_plane::set_global_rule_mode),
                )
                .route(
                    "/v1/admin/policy/routes/upsert",
                    post(control_plane::upsert_route_override),
                )
                .route(
                    "/v1/admin/policy/routes/delete",
                    post(control_plane::delete_route_override),
                )
                .route(
                    "/v1/admin/policy/rate-limits/upsert",
                    post(control_plane::upsert_route_rate_limit),
                )
                .route(
                    "/v1/admin/policy/rate-limits/delete",
                    post(control_plane::delete_route_rate_limit),
                )
                .route(
                    "/v1/admin/recommendations/demo",
                    get(control_plane::demo_recommendations),
                )
                .route(
                    "/v1/admin/commands/demo",
                    get(control_plane::demo_one_click_commands),
                )
                .route(
                    "/v1/admin/mitigations/active",
                    get(control_plane::list_active_blocks),
                )
                .route(
                    "/v1/admin/reputations",
                    get(control_plane::list_reputations),
                )
                .route(
                    "/v1/admin/reputations/{ip}",
                    get(control_plane::get_reputation),
                )
                .route(
                    "/v1/admin/reputations/reset/{ip}",
                    post(control_plane::reset_reputation),
                )
                .route(
                    "/v1/admin/mitigations/unblock/{ip}",
                    post(control_plane::unblock_ip),
                )
                .route(
                    "/v1/admin/mitigations/block",
                    post(control_plane::manual_block_ip),
                )
                .route("/v1/admin/events/recent", get(control_plane::recent_events))
                .route("/v1/admin/events/search", get(control_plane::search_events))
                .route("/v1/admin/audits/recent", get(control_plane::recent_audits))
                .route("/v1/admin/metrics", get(control_plane::metrics))
                .route(
                    "/v1/admin/sources/clear/{ip}",
                    post(control_plane::clear_source),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes",
                    get(control_plane::shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/persisted",
                    get(control_plane::persisted_shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/sync",
                    post(control_plane::sync_shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/clear",
                    post(control_plane::clear_shadow_routes),
                )
                .route(
                    "/v1/admin/behavior/baselines",
                    get(control_plane::behavior_baselines),
                )
                .route(
                    "/v1/admin/behavior/baselines/clear",
                    post(control_plane::clear_behavior_baselines),
                )
                .route(
                    "/v1/admin/behavior/snapshots/persist",
                    post(control_plane::persist_behavior_snapshots),
                )
                .route(
                    "/v1/admin/behavior/snapshots/persisted",
                    get(control_plane::persisted_behavior_snapshots),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/approved",
                    get(control_plane::approved_shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/approve",
                    post(control_plane::approve_shadow_route),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/approved/delete",
                    post(control_plane::delete_approved_shadow_route),
                )
                .route(
                    "/v1/admin/policy/route-behavior-overrides",
                    get(control_plane::list_route_behavior_overrides),
                )
                .route(
                    "/v1/admin/policy/route-behavior-overrides/upsert",
                    post(control_plane::upsert_route_behavior_override),
                )
                .route(
                    "/v1/admin/policy/route-behavior-overrides/delete",
                    post(control_plane::delete_route_behavior_override),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/raw",
                    get(control_plane::raw_shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/shadow-routes/filtered",
                    get(control_plane::filtered_shadow_routes),
                )
                .route(
                    "/v1/admin/discovery/promoted-spec-routes",
                    get(control_plane::promoted_spec_routes),
                )
                .route(
                    "/v1/admin/discovery/promote-shadow-route",
                    post(control_plane::promote_shadow_route),
                )
                .route(
                    "/v1/admin/discovery/promoted-spec-routes/delete",
                    post(control_plane::delete_promoted_spec_route),
                )
                .route(
                    "/v1/admin/discovery/managed-spec-routes",
                    get(control_plane::managed_spec_routes),
                )
                .route(
                    "/v1/admin/discovery/promote-to-managed-spec",
                    post(control_plane::promote_to_managed_spec),
                )
                .route(
                    "/v1/admin/discovery/managed-spec-routes/delete",
                    post(control_plane::delete_managed_spec_route),
                )
                .route(
                    "/v1/admin/suppressions",
                    get(control_plane::analyst_suppressions),
                )
                .route(
                    "/v1/admin/suppressions/upsert",
                    post(control_plane::upsert_analyst_suppression),
                )
                .route(
                    "/v1/admin/suppressions/delete",
                    post(control_plane::delete_analyst_suppression),
                )
                .route(
                    "/v1/admin/allowlists/sources",
                    get(control_plane::source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/sources/upsert",
                    post(control_plane::upsert_source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/sources/delete",
                    post(control_plane::delete_source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals",
                    get(control_plane::principal_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals/upsert",
                    post(control_plane::upsert_principal_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals/delete",
                    post(control_plane::delete_principal_allowlist),
                )
                .route(
                    "/v1/admin/policy/export",
                    get(control_plane::export_live_policy),
                )
                .route(
                    "/v1/admin/policy/import",
                    post(control_plane::import_live_policy),
                )
                .route(
                    "/v1/admin/response-contracts",
                    get(control_plane::response_contracts),
                )
                .route(
                    "/v1/admin/response-contracts/upsert",
                    post(control_plane::upsert_response_contract),
                )
                .route(
                    "/v1/admin/response-contracts/delete",
                    post(control_plane::delete_response_contract),
                )
                .route(
                    "/v1/admin/policy/bundles",
                    get(control_plane::policy_bundles),
                )
                .route(
                    "/v1/admin/policy/bundles/save",
                    post(control_plane::save_policy_bundle),
                )
                .route(
                    "/v1/admin/policy/bundles/restore",
                    post(control_plane::restore_policy_bundle),
                )
                .route(
                    "/v1/admin/policy/diff/latest",
                    get(control_plane::latest_policy_diff),
                )
                .route(
                    "/v1/admin/allowlists/sources/scoped",
                    get(control_plane::scoped_source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/sources/scoped/upsert",
                    post(control_plane::upsert_scoped_source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/sources/scoped/delete",
                    post(control_plane::delete_scoped_source_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals/scoped",
                    get(control_plane::scoped_principal_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals/scoped/upsert",
                    post(control_plane::upsert_scoped_principal_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/principals/scoped/delete",
                    post(control_plane::delete_scoped_principal_allowlist),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/export",
                    get(control_plane::export_managed_spec_inventory),
                )
                .route(
                    "/v1/admin/allowlists/tri-scoped",
                    get(control_plane::tri_scoped_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/tri-scoped/upsert",
                    post(control_plane::upsert_tri_scoped_allowlist),
                )
                .route(
                    "/v1/admin/allowlists/tri-scoped/delete",
                    post(control_plane::delete_tri_scoped_allowlist),
                )
                .route(
                    "/v1/admin/policy/bundles/verify/latest",
                    get(control_plane::verify_policy_bundle_latest),
                )
                .route(
                    "/v1/admin/policy/bundles/verify",
                    post(control_plane::verify_policy_bundle_by_id),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/export/enforcement",
                    get(control_plane::export_enforcement_managed_spec_inventory),
                )
                .route(
                    "/v1/admin/response-contracts/approve",
                    post(control_plane::approve_response_contract),
                )
                .route(
                    "/v1/admin/policy/bundles/tamper",
                    post(control_plane::tamper_policy_bundle),
                )
                .route(
                    "/v1/admin/response-contracts/approve-from-event",
                    post(control_plane::approve_response_contract_from_event),
                )
                .route(
                    "/v1/admin/policy/timeline",
                    get(control_plane::policy_timeline),
                )
                .route(
                    "/v1/admin/policy/timeline/filtered",
                    get(control_plane::policy_timeline_filtered),
                )
                .route(
                    "/v1/admin/policy/restore-refusals",
                    get(control_plane::restore_refusals),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/release-state",
                    get(control_plane::managed_spec_release_state),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/release-state/upsert",
                    post(control_plane::upsert_managed_spec_release_state),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/release-state/delete",
                    post(control_plane::delete_managed_spec_release_state),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/export/gateway",
                    get(control_plane::export_gateway_managed_spec_inventory),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/release-state/promote",
                    post(control_plane::promote_managed_spec_release),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/export/api-gateway-policy",
                    get(control_plane::export_api_gateway_policy),
                )
                .route(
                    "/v1/admin/discovery/managed-spec/export/manifest",
                    get(control_plane::export_manifest),
                )
                .route(
                    "/v1/admin/policy/timeline/page",
                    get(control_plane::policy_timeline_page),
                )
                .route(
                    "/v1/admin/policy/restore-refusal-alerts",
                    get(control_plane::restore_refusal_alerts),
                )
                .route(
                    "/v1/admin/policy/restore-refusal-alerts/ack",
                    post(control_plane::acknowledge_restore_refusal_alert),
                )
                .route(
                    "/v1/admin/policy/restore-refusal-alerts/resolve",
                    post(control_plane::resolve_restore_refusal_alert),
                )
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    core::admin_auth_middleware,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    core::request_context_middleware,
                )),
        )
        .layer(cors)
        .with_state(state)
}
