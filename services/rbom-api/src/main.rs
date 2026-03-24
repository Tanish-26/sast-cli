use axum::{http::StatusCode, response::IntoResponse, routing::get, routing::post, Json, Router};
use rbom::RbomScore;
use sast_core::Finding;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

#[derive(Debug, Deserialize)]
struct ScoreRequest {
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct ScoreResponse {
    rbom: RbomScore,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rbom_api=info,tower_http=info".into()),
        )
        .init();

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/score", post(score))
        .layer(TraceLayer::new_for_http());

    let addr = std::env::var("RBOM_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn score(Json(req): Json<ScoreRequest>) -> impl IntoResponse {
    let rbom = rbom::score(&req.findings);
    (StatusCode::OK, Json(ScoreResponse { rbom })).into_response()
}

