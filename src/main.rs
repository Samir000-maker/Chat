use axum::{routing::get, Router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Create basic router responding on /
    let app = Router::new().route("/", get(|| async { "Hello, Render Rust!" }));

    // Read the PORT environment variable (Render sets this automatically)
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "10000".into())
        .parse()
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on {:?}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
