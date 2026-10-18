//! Runnable Google Drive style API demonstrating application-owned authorization.

mod api;
mod auth;
mod drive;
mod error;

/// Seeds the repository, starts the HTTP server, and drains requests on Ctrl-C.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = api::router(drive::Drive::seeded().await?);
    let address = std::env::var("DRIVE_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3001".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("Drive API listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("shutdown signal error: {error}");
            }
        })
        .await?;
    Ok(())
}
