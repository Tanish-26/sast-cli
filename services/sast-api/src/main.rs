use axum::{http::StatusCode, response::IntoResponse, routing::get, routing::post, Json, Router};
use rbom::RbomScore;
use sast_core::{poc, Finding, Language};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;

#[derive(Debug, Deserialize)]
struct ScanRequest {
    /// Source code to scan.
    code: String,
    /// Language (only `javascript` supported right now).
    language: Option<Language>,
    /// Optional logical filename/path for findings.
    path: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    findings: Vec<Finding>,
    rbom: RbomScore,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sast_api=info,tower_http=info".into()),
        )
        .init();

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/scan", post(scan))
        .layer(TraceLayer::new_for_http());

    let addr = std::env::var("SAST_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}

async fn scan(Json(req): Json<ScanRequest>) -> impl IntoResponse {
    let lang = req.language.unwrap_or(Language::JavaScript);
    let path = req.path.unwrap_or_else(|| "<memory>".to_string());

    let scan_result = match lang {
        Language::JavaScript => sast_js::scan_eval_taint(&req.code, &path),
        Language::C | Language::Cpp => sast_c::scan(&req.code, &path, lang),
    };

    match scan_result {
        Ok(mut findings) => {
            poc::attach(&mut findings);
            let rbom = rbom::score(&findings);
            (StatusCode::OK, Json(ScanResponse { findings, rbom })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}
