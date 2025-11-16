use anyhow::Result;
use deepsys_cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.execute().await
}
