//! K-FS-READ-SCOPE — `OCSERVE_WORKING_DIR` decides which directories beside the
//! server cwd a request may scope a file read to. One test function, because
//! the variable is process-global.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ocserve_http::AppState;
use tower::ServiceExt;

async fn get(dir: &str) -> StatusCode {
    let app = ocserve_http::router(AppState::with_payloads_and_v2(
        None,
        ocserve_http::Payloads::default(),
        true,
    ));
    let req = Request::builder()
        .method("GET")
        .uri("/api/fs/read/a.txt")
        .header("x-opencode-directory", dir)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn scope_roots_env_replaces_the_home_default() {
    // A project outside the cwd and (almost certainly) outside home.
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("a.txt"), b"x").unwrap();
    let dir = outside.path().to_str().unwrap();

    // Default roots (cwd + home): the system temp dir is neither.
    unsafe { std::env::remove_var("OCSERVE_WORKING_DIR") };
    assert_eq!(get(dir).await, StatusCode::BAD_REQUEST);

    // Listed as a root, it is accepted.
    unsafe { std::env::set_var("OCSERVE_WORKING_DIR", dir) };
    assert_eq!(get(dir).await, StatusCode::OK);

    // A set-but-empty value replaces home with nothing: only the cwd remains.
    unsafe { std::env::set_var("OCSERVE_WORKING_DIR", "") };
    assert_eq!(get(dir).await, StatusCode::BAD_REQUEST);

    // A relative or missing root is ignored (fails closed).
    unsafe { std::env::set_var("OCSERVE_WORKING_DIR", "relative:/definitely/missing") };
    assert_eq!(get(dir).await, StatusCode::BAD_REQUEST);
    unsafe { std::env::remove_var("OCSERVE_WORKING_DIR") };
}
