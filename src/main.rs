mod api;
mod config;
mod error;
mod loader;
mod sign;
mod version;

use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let base = std::env::current_dir().expect("failed to get current directory");

    // Load config
    let cfg = config::Config::load_or_default(&base.join("config.toml"));
    tracing::info!("config: {}:{}", cfg.server.host, cfg.server.port);

    // Detect version and load version data
    let runtime_dir = base.join("runtime");
    let runtime_app = runtime_dir.join("app");
    let versions_dir = base.join("versions");
    let ver = version::load(&runtime_app, &versions_dir)
        .unwrap_or_else(|e| {
            tracing::error!("failed to load version data: {}", e);
            std::process::exit(1);
        });
    tracing::info!("version: {} (sign_offset: 0x{:x})", ver.version_key, ver.sign_offset);

    // Extract platform and version for sign response
    let appinfo = &ver.appinfo;
    let platform = appinfo["Os"].as_str().unwrap_or("Linux").to_string();
    let version_str = appinfo["CurrentVersion"].as_str().unwrap_or("unknown").to_string();

    // Load wrapper.node and get sign function
    let signer = loader::Signer::load(&runtime_dir, ver.sign_offset)
        .unwrap_or_else(|e| {
            tracing::error!("failed to load signer: {}", e);
            std::process::exit(1);
        });

    // Build app state
    let state = Arc::new(api::AppState {
        signer: Mutex::new(signer),
        appinfo: ver.appinfo,
        platform,
        version: version_str,
    });

    // Build router and start server
    let app = api::router(state);
    let addr = format!("{}:{}", cfg.server.host, cfg.server.port);
    tracing::info!("starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
