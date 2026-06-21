//! `ortd` — the ORT server daemon.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use ort_cli::{hex, init_tracing, read_key, write_key};
use ort_core::handshake::{ServerConfig, SuiteKey};
use ort_core::suite::agile::ServerKemKey;
use ort_core::suite::SuiteId;
use ort_net::run_server;
use tokio::net::TcpListener;

/// Suites the server can hold keys for.
const ALL_SUITES: [SuiteId; 2] = [SuiteId::MlKem768MlDsa65, SuiteId::X25519Ed25519];

fn suite_name(id: SuiteId) -> &'static str {
    match id {
        SuiteId::MlKem768MlDsa65 => "pqc",
        SuiteId::X25519Ed25519 => "ecdh",
    }
}
fn kem_file(id: SuiteId) -> String {
    format!("kem_{}.key", suite_name(id))
}
fn cert_file(id: SuiteId) -> String {
    format!("cert_{}.der", suite_name(id))
}
fn cert_signing_file(id: SuiteId) -> String {
    format!("cert_{}_signing.key", suite_name(id))
}

fn parse_suites(s: &str) -> Result<Vec<SuiteId>> {
    if s == "all" {
        return Ok(ALL_SUITES.to_vec());
    }
    s.split(',')
        .map(|p| {
            SuiteId::from_name(p.trim())
                .ok_or_else(|| anyhow::anyhow!("unknown suite '{}' (expected pqc, ecdh or all)", p.trim()))
        })
        .collect()
}

#[derive(Parser)]
#[command(
    name = "ortd",
    version,
    about = "ORT server: terminate ORT tunnels and forward to a target"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the server (also the default when no subcommand is given).
    Run(RunArgs),
    /// Generate server KEM keypair(s) and print the public key(s).
    GenKey(GenArgs),
    /// Generate (or reuse) KEM key(s) + self-signed cert(s) binding the key(s).
    GenCert(GenArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Address to listen for ORT connections on.
    #[arg(long)]
    listen: SocketAddr,
    /// Backend target to forward decrypted plaintext to.
    #[arg(long)]
    target: SocketAddr,
    /// Directory holding per-suite keys (and optional certs). If omitted,
    /// ephemeral keys for all suites are generated.
    #[arg(long)]
    cert: Option<PathBuf>,
    /// Anti-replay acceptance window in milliseconds.
    #[arg(long, default_value_t = 2000)]
    window_ms: u64,
    /// Permitted clock skew (future tolerance) in milliseconds.
    #[arg(long, default_value_t = 1000)]
    skew_ms: u64,
}

#[derive(Args)]
struct GenArgs {
    /// Output directory for the generated keys/certs.
    #[arg(long, default_value = "./cert")]
    out: PathBuf,
    /// Which suites to generate for: `v1`, `v2`, comma-separated, or `all`.
    #[arg(long, default_value = "all")]
    suite: String,
}

fn load_or_make_kem(dir: &Path, id: SuiteId) -> Result<ServerKemKey> {
    let path = dir.join(kem_file(id));
    if path.exists() {
        let seed = read_key(&path)?;
        ServerKemKey::from_seed(id, &seed).context("decode server KEM key")
    } else {
        let key = ServerKemKey::generate(id);
        write_key(&path, &key.to_seed())?;
        Ok(key)
    }
}

fn gen_key(args: GenArgs) -> Result<()> {
    for id in parse_suites(&args.suite)? {
        let key = load_or_make_kem(&args.out, id)?;
        println!("[{}] server_pk: {}", suite_name(id), hex(&key.public()));
    }
    println!("keys in {}", args.out.display());
    Ok(())
}

fn gen_cert(args: GenArgs) -> Result<()> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    for id in parse_suites(&args.suite)? {
        let key = load_or_make_kem(&args.out, id)?;
        let server_pk = key.public();

        // Reuse the cert signing key across runs so re-issuing a cert keeps a
        // stable X.509 identity (clients pinning the cert keep working).
        let signing_path = args.out.join(cert_signing_file(id));
        let kp = if signing_path.exists() {
            let der = read_key(&signing_path)?;
            KeyPair::try_from(&der[..]).context("load cert signing key")?
        } else {
            let kp = KeyPair::generate_for(&PKCS_ED25519).context("generate cert key")?;
            write_key(&signing_path, kp.serialize_der().as_slice())?;
            kp
        };

        // Standard X.509 certificate (no custom extensions)
        let params = CertificateParams::new(vec!["ortd".to_string()]).context("cert params")?;
        let cert = params.self_signed(&kp).context("self-sign cert")?;
        std::fs::write(args.out.join(cert_file(id)), cert.der().as_ref()).context("write cert")?;
        println!(
            "[{}] wrote cert; server_pk: {}",
            suite_name(id),
            hex(&server_pk)
        );
    }
    Ok(())
}

fn load_server_config(args: &RunArgs) -> Result<ServerConfig> {
    let mut suites = Vec::new();
    for id in ALL_SUITES {
        let key = match &args.cert {
            Some(dir) if dir.join(kem_file(id)).exists() => {
                let seed = read_key(&dir.join(kem_file(id)))?;
                ServerKemKey::from_seed(id, &seed).context("decode KEM key")?
            }
            Some(_) => continue,                // this suite not configured
            None => ServerKemKey::generate(id), // ephemeral for all suites
        };
        let certificate = args
            .cert
            .as_ref()
            .map(|d| d.join(cert_file(id)))
            .filter(|p| p.exists())
            .map(std::fs::read)
            .transpose()
            .context("reading certificate")?
            .unwrap_or_default();

        // Load certificate signing key (for Half-RTT authentication)
        // Note: gen_cert uses Ed25519 for all suites' certificates (regardless of KEM)
        let cert_signing_key = args
            .cert
            .as_ref()
            .map(|d| d.join(cert_signing_file(id)))
            .filter(|p| p.exists())
            .map(|p| {
                let der = read_key(&p)?;
                // Use proper PKCS#8 parser to extract the Ed25519 seed
                // (avoids tail-slice heuristic that breaks on v2 format)
                let key_info = pkcs8::PrivateKeyInfo::try_from(der.as_slice())
                    .context("parse PKCS#8 private key")?;
                let seed = key_info.private_key;
                if seed.len() != 32 {
                    anyhow::bail!("Ed25519 seed must be 32 bytes, got {}", seed.len());
                }
                // Certificate signing always uses Ed25519 (X25519Ed25519 suite)
                ort_core::suite::agile::SigIdentity::from_seed(SuiteId::X25519Ed25519, seed)
                    .context("parse cert signing key")
            })
            .transpose()?;

        tracing::info!(suite = suite_name(id), server_pk = %hex(&key.public()), "loaded suite");
        suites.push(SuiteKey { key, certificate, cert_signing_key });
    }
    if suites.is_empty() {
        anyhow::bail!("no server keys found in --cert dir (run `ortd gen-key` first)");
    }
    Ok(ServerConfig {
        suites,
        window_ms: args.window_ms,
        skew_ms: args.skew_ms,
    })
}

async fn run(args: RunArgs) -> Result<()> {
    if args.cert.is_none() {
        tracing::warn!("no --cert dir; generating ephemeral keys for all suites");
    }
    let scfg = Arc::new(load_server_config(&args)?);
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, target = %args.target, "ortd listening");
    run_server(listener, args.target, scfg).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.len() > 1 {
        let a = argv[1].to_string_lossy();
        let known = matches!(
            a.as_ref(),
            "run" | "gen-key" | "gen-cert" | "help" | "-h" | "--help" | "-V" | "--version"
        );
        if !known {
            argv.insert(1, std::ffi::OsString::from("run"));
        }
    }
    match Cli::parse_from(argv).command {
        Commands::GenKey(a) => gen_key(a),
        Commands::GenCert(a) => gen_cert(a),
        Commands::Run(a) => run(a).await,
    }
}
