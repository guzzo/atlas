use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    routing::{get, post},
};
use passport_policy_proof::*;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Semaphore;

type Response = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(code: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"code":code})))
}
async fn work<F>(sem: Arc<Semaphore>, f: F) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    let permit = sem
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, Json(json!({"code":"busy"}))))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .map_err(|_| error("unavailable"))?
}
#[tokio::main]
async fn main() {
    validated_policy().expect("validated Cedar policy");
    let sem = Arc::new(Semaphore::new(2));
    let zk = std::env::var("ENABLE_ZK").unwrap_or("1".into()) == "1";
    let s = sem.clone();
    let mut app = Router::new()
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route(
            "/v0/verify",
            post(move |Json(i): Json<ProofInput>| {
                let s = s.clone();
                async move {
                    if !zk {
                        return Err(error("feature_disabled"));
                    };
                    work(s, move || {
                        Ok(Json(json!({"valid":verify(&i).unwrap_or(false)})))
                    })
                    .await
                }
            }),
        );
    if std::env::var("MODE").unwrap_or("verify".into()) == "acme" {
        let s = sem.clone();
        app = app
            .route(
                "/v0/commit",
                post(|Json(i): Json<CommitInput>| async move { Json(commit(i.limit)) }),
            )
            .route(
                "/v0/decide",
                post(move |Json(i): Json<DecisionInput>| {
                    let s = s.clone();
                    async move {
                        work(s, move || {
                            Ok(Json(
                                json!({"allowed":decide(&i).map_err(|_|error("denied"))?}),
                            ))
                        })
                        .await
                    }
                }),
            );
        let s = sem.clone();
        app = app.route(
            "/v0/prove",
            post(move |Json(i): Json<ProveInput>| {
                let s = s.clone();
                async move {
                    if !zk {
                        return Err(error("feature_disabled"));
                    };
                    work(s, move || {
                        Ok(Json(
                            json!({"program":PROGRAM,"proof":prove(&i).map_err(error)?}),
                        ))
                    })
                    .await
                }
            }),
        );
    }
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8090").await.unwrap();
    eprintln!("passport policy/proof worker ready");
    axum::serve(listener, app.layer(DefaultBodyLimit::max(32768)))
        .await
        .unwrap();
}
