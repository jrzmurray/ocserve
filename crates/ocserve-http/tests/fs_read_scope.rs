//! K-FS-READ-SCOPE — `GET /api/fs/read/*path` reads from the REQUEST's
//! directory, not the server cwd, and still refuses to leave it.
//!
//! The remote dispatcher reads `.opencode-dispatch.json` from the project via
//! this route with `x-opencode-directory`. Resolved against the server cwd it
//! was a 404, which the dispatcher treats as "no bootstrap hook".

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ocserve_http::AppState;
use tower::ServiceExt;

fn app() -> axum::Router {
    ocserve_http::router(AppState::with_payloads_and_v2(
        None,
        ocserve_http::Payloads::default(),
        true,
    ))
}

/// A fresh directory beneath the server cwd, which the route accepts as a
/// scope (the system temp dir is outside both allowed roots).
fn inside_root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("fs-read-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap()
}

async fn get(uri: &str, headers: &[(&str, &str)]) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method("GET").uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = app()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let st = resp.status();
    let b = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (st, b.to_vec())
}

#[tokio::test]
async fn header_scopes_the_read_to_the_requested_project() {
    let project = inside_root();
    std::fs::write(
        project.path().join(".opencode-dispatch.json"),
        b"{\"bootstrap\":\"x\"}",
    )
    .unwrap();
    let dir = project.path().to_str().unwrap();
    let (st, body) = get(
        "/api/fs/read/.opencode-dispatch.json",
        &[("x-opencode-directory", dir)],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"{\"bootstrap\":\"x\"}");
}

#[tokio::test]
async fn location_query_and_percent_encoded_header_scope_the_read() {
    let parent = inside_root();
    let project = parent.path().join("my project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("a.txt"), b"hi").unwrap();
    let dir = project.to_str().unwrap();
    let enc = dir.replace(' ', "%20");
    let (st, body) = get(
        &format!("/api/fs/read/a.txt?location[directory]={enc}"),
        &[],
    )
    .await;
    assert_eq!((st, body.as_slice()), (StatusCode::OK, &b"hi"[..]));
    let (st, body) = get(
        "/api/fs/read/a.txt",
        &[("x-opencode-directory", enc.as_str())],
    )
    .await;
    assert_eq!((st, body.as_slice()), (StatusCode::OK, &b"hi"[..]));
}

#[tokio::test]
async fn a_file_that_only_exists_in_the_server_directory_is_not_found() {
    // Cargo.toml exists in the server cwd (the crate dir) but not in the project.
    let project = inside_root();
    let dir = project.path().to_str().unwrap();
    let (st, _) = get("/api/fs/read/Cargo.toml", &[("x-opencode-directory", dir)]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dot_dot_and_symlink_escapes_are_refused_inside_the_scoped_base() {
    let outer = inside_root();
    let project = outer.path().join("proj");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(outer.path().join("secret.txt"), b"nope").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outer.path().join("secret.txt"), project.join("link")).unwrap();
    let dir = project.to_str().unwrap();
    let h = [("x-opencode-directory", dir)];
    let (st, body) = get("/api/fs/read/..%2Fsecret.txt", &h).await;
    assert_ne!(st, StatusCode::OK, "dot-dot must not escape");
    assert_ne!(body, b"nope");
    #[cfg(unix)]
    {
        let (st, body) = get("/api/fs/read/link", &h).await;
        assert_ne!(
            st,
            StatusCode::OK,
            "symlink out of the project must not be read"
        );
        assert_ne!(body, b"nope");
    }
}

#[tokio::test]
async fn a_scope_outside_the_server_cwd_and_home_is_refused() {
    // /etc exists on every unix host and is outside cwd and home.
    for d in ["/etc", "/tmp/../etc", "/definitely/missing"] {
        let (st, body) = get("/api/fs/read/hosts", &[("x-opencode-directory", d)]).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{d}");
        assert!(!String::from_utf8_lossy(&body).contains("localhost"), "{d}");
    }
}

#[tokio::test]
async fn a_regular_file_is_not_a_valid_scope() {
    let project = inside_root();
    std::fs::write(project.path().join("f.txt"), b"data").unwrap();
    let file = project.path().join("f.txt");
    let (st, body) = get(
        "/api/fs/read/.",
        &[("x-opencode-directory", file.to_str().unwrap())],
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_ne!(body, b"data");
}

#[cfg(unix)]
#[tokio::test]
async fn a_scope_that_is_a_symlink_out_of_the_roots_is_refused() {
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("a.txt"), b"secret").unwrap();
    let inside = inside_root();
    let link = inside.path().join("link");
    std::os::unix::fs::symlink("/etc", &link).unwrap();
    let (st, body) = get(
        "/api/fs/read/hosts",
        &[("x-opencode-directory", link.to_str().unwrap())],
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert!(!String::from_utf8_lossy(&body).contains("localhost"));
}

#[cfg(unix)]
#[tokio::test]
async fn a_fifo_never_blocks_the_read_or_the_scope() {
    let project = inside_root();
    let fifo = project.path().join("pipe");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let dir = project.path().to_str().unwrap();
    let h1 = [("x-opencode-directory", dir)];
    let fut = get("/api/fs/read/pipe", &h1);
    let (st, _) = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("a FIFO inside the project must not hang the read");
    assert_eq!(st, StatusCode::NOT_FOUND);
    let h2 = [("x-opencode-directory", fifo.to_str().unwrap())];
    let fut = get("/api/fs/read/x", &h2);
    let (st, _) = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .expect("a FIFO as the scope must not hang");
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_file_over_the_read_cap_is_refused() {
    let project = inside_root();
    let f = std::fs::File::create(project.path().join("big.bin")).unwrap();
    f.set_len(64 * 1024 * 1024 + 1).unwrap();
    let dir = project.path().to_str().unwrap();
    let (st, _) = get("/api/fs/read/big.bin", &[("x-opencode-directory", dir)]).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
    f.set_len(1024).unwrap();
    let (st, body) = get("/api/fs/read/big.bin", &[("x-opencode-directory", dir)]).await;
    assert_eq!((st, body.len()), (StatusCode::OK, 1024));
}
