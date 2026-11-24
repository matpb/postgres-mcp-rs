#[tokio::main]
async fn main() -> std::process::ExitCode {
    postgres_mcp::run().await
}
