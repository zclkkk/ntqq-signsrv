use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::{Arc, Mutex};

use crate::loader::Signer;
use crate::sign;

pub struct AppState {
    pub signer: Mutex<Signer>,
    pub appinfo: Value,
    pub platform: String,
    pub version: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", post(handle_sign))
        .route("/appinfo", get(handle_appinfo))
        .with_state(state)
}

#[derive(Deserialize)]
struct SignRequest {
    cmd: String,
    src: String,
    seq: i32,
}

#[derive(Serialize)]
struct SignResponse {
    platform: String,
    version: String,
    value: SignValue,
}

#[derive(Serialize)]
struct SignValue {
    sign: String,
    token: String,
    extra: String,
}

async fn handle_sign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let src = match hex::decode(&req.src) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    };

    let signer = state.signer.lock().unwrap();
    let (buf, _ret) = signer.sign(&req.cmd, &src, req.seq);
    let output = sign::parse_output(&buf);

    Json(SignResponse {
        platform: state.platform.clone(),
        version: state.version.clone(),
        value: SignValue {
            sign: hex::encode(&output.sign),
            token: hex::encode(&output.token),
            extra: hex::encode(&output.extra),
        },
    }).into_response()
}

async fn handle_appinfo(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(state.appinfo.clone())
}
