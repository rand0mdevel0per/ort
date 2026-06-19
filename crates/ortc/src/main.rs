//! `ortc` — the ORT client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use ort_cli::{hex, init_tracing, read_key, write_key};
use ort_core::handshake::ClientConfig;
use ort_core::suite::v1::V1;
use ort_core::suite::CipherSuite;
use ort_net::{run_client, ServerVerifier};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "ortc", version, about = "ORT client: tunnel local TCP to an ortd")]
struct Cli {
    /// Local address to listen on for application connections.
    #[arg(long)]
    listen: SocketAddr,
    /// Remote ortd endpoint to tunnel to.
    #[arg(long)]
    target: SocketAddr,
    /// Skip strict certificate validation; trust the server key on first use.
    #[arg(long)]
    no_strict_cert: bool,
    /// Client signing key file (ML-DSA seed). Generated if the path is absent.
    #[arg(long)]
    client_key: Option<PathBuf>,
    /// DER CA certificate to anchor strict verification to. If omitted in
    /// strict mode, the server certificate must be validly self-signed.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Always use 1-RTT (disable 0-RTT resumption).
    #[arg(long)]
    force_1rtt: bool,
}

fn load_client_config(args: &Cli) -> Result<ClientConfig<V1>> {
    let sig_secret = match &args.client_key {
        Some(path) if path.exists() => {
            let seed = read_key(path)?;
            V1::sig_secret_from_bytes(&seed).context("decode client signing key")?
        }
        Some(path) => {
            let s = V1::sig_generate();
            write_key(path, &V1::sig_secret_to_bytes(&s))?;
            tracing::info!(path = %path.display(), "generated new client signing key");
            s
        }
        None => {
            tracing::info!("using an ephemeral client signing key for this run");
            V1::sig_generate()
        }
    };
    let client_pk = V1::sig_public(&sig_secret);
    tracing::info!(client_pk = %hex(&client_pk), "client public key");
    Ok(ClientConfig { sig_secret, client_pk })
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Cli::parse();

    let verifier = if args.no_strict_cert {
        ServerVerifier::TrustOnFirstUse
    } else {
        let ca = args
            .ca
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .context("reading CA certificate")?;
        ServerVerifier::Strict { ca }
    };

    let ccfg = Arc::new(load_client_config(&args)?);
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, target = %args.target, "ortc listening");

    run_client(listener, args.target, ccfg, verifier, args.force_1rtt).await?;
    Ok(())
}
