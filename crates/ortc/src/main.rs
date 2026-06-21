//! `ortc` — the ORT client.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use ort_cli::{hex, init_tracing, read_key, write_key};
use ort_core::handshake::ClientConfig;
use ort_core::suite::agile::SigIdentity;
use ort_core::suite::SuiteId;
use ort_net::{run_client, ClientParams, ServerVerifier};
use tokio::net::TcpListener;

fn parse_suite(s: &str) -> Result<SuiteId> {
    SuiteId::from_name(s.trim())
        .ok_or_else(|| anyhow::anyhow!("unknown suite '{}' (expected pqc or ecdh)", s.trim()))
}

fn parse_suites(s: &str) -> Result<Vec<SuiteId>> {
    s.split(',').map(parse_suite).collect()
}

#[derive(Parser)]
#[command(
    name = "ortc",
    version,
    about = "ORT client: tunnel local TCP to an ortd"
)]
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
    /// DER CA certificate to anchor strict verification to (else self-signed).
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Signature algorithm for the client identity: `pqc` (ML-DSA) or `ecdh` (Ed25519).
    #[arg(long, default_value = "pqc")]
    sig_alg: String,
    /// KEM suites to offer, in preference order (e.g. `pqc,ecdh`).
    #[arg(long, default_value = "pqc,ecdh")]
    suites: String,
    /// Client signing key file (seed). Generated if the path is absent.
    #[arg(long)]
    client_key: Option<PathBuf>,
    /// Always use 1-RTT (disable 0-RTT resumption).
    #[arg(long)]
    force_1rtt: bool,
}

fn load_identity(args: &Cli, sig_alg: SuiteId) -> Result<SigIdentity> {
    match &args.client_key {
        Some(path) if path.exists() => {
            let seed = read_key(path)?;
            SigIdentity::from_seed(sig_alg, &seed).context("decode client signing key")
        }
        Some(path) => {
            let id = SigIdentity::generate(sig_alg);
            write_key(path, &id.to_seed())?;
            tracing::info!(path = %path.display(), "generated new client signing key");
            Ok(id)
        }
        None => {
            tracing::info!("using an ephemeral client signing key for this run");
            Ok(SigIdentity::generate(sig_alg))
        }
    }
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

    let sig_alg = parse_suite(&args.sig_alg)?;
    let kem_suites = parse_suites(&args.suites)?;
    let identity = load_identity(&args, sig_alg)?;
    let cfg = ClientConfig::new(identity);
    tracing::info!(client_pk = %hex(&cfg.client_pk), sig_alg = %args.sig_alg, "client identity");

    let params = Arc::new(ClientParams {
        cfg,
        kem_suites,
        verifier,
        force_1rtt: args.force_1rtt,
    });
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, target = %args.target, "ortc listening");

    run_client(listener, args.target, params).await?;
    Ok(())
}
