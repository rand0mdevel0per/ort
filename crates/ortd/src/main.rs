//! `ortd` — the ORT server daemon.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

use ort_cli::{hex, init_tracing, read_key, write_key};
use ort_core::handshake::ServerConfig;
use ort_core::suite::v1::V1;
use ort_core::suite::CipherSuite;
use ort_net::{run_server, SERVERPK_OID_U64};
use tokio::net::TcpListener;

const KEM_KEY_FILE: &str = "server_kem.key";
const SIGN_KEY_FILE: &str = "server_sign.key";
const CERT_FILE: &str = "cert.der";

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
    /// Generate a server KEM + signing keypair and print the public key.
    GenKey(GenKeyArgs),
    /// Generate (or reuse) a server key and a self-signed certificate that
    /// binds the ML-KEM public key via a custom extension.
    GenCert(GenKeyArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Address to listen for ORT connections on.
    #[arg(long)]
    listen: SocketAddr,
    /// Backend target to forward decrypted plaintext to.
    #[arg(long)]
    target: SocketAddr,
    /// Directory holding the server key (and optional cert). If omitted, an
    /// ephemeral key is generated (clients must use --no-strict-cert TOFU).
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
struct GenKeyArgs {
    /// Output directory for the generated keys.
    #[arg(long, default_value = "./cert")]
    out: PathBuf,
}

fn gen_key(args: GenKeyArgs) -> Result<()> {
    let kem = V1::kem_generate();
    let sign = V1::sig_generate();
    let server_pk = V1::kem_public(&kem);

    write_key(&args.out.join(KEM_KEY_FILE), &V1::kem_secret_to_bytes(&kem))?;
    write_key(&args.out.join(SIGN_KEY_FILE), &V1::sig_secret_to_bytes(&sign))?;

    println!("generated server keys in {}", args.out.display());
    println!("server_pk (pin this on clients): {}", hex(&server_pk));
    Ok(())
}

fn load_or_make_kem(dir: &std::path::Path) -> Result<ort_core::suite::v1::KemSecret> {
    let path = dir.join(KEM_KEY_FILE);
    if path.exists() {
        let seed = read_key(&path)?;
        V1::kem_secret_from_bytes(&seed).context("decode server KEM key")
    } else {
        let kem = V1::kem_generate();
        write_key(&path, &V1::kem_secret_to_bytes(&kem))?;
        let sign = V1::sig_generate();
        write_key(&dir.join(SIGN_KEY_FILE), &V1::sig_secret_to_bytes(&sign))?;
        Ok(kem)
    }
}

fn gen_cert(args: GenKeyArgs) -> Result<()> {
    use rcgen::{CertificateParams, CustomExtension, KeyPair, PKCS_ED25519};

    let kem = load_or_make_kem(&args.out)?;
    let server_pk = V1::kem_public(&kem);

    let key_pair = KeyPair::generate_for(&PKCS_ED25519).context("generate cert key")?;
    let mut params = CertificateParams::new(vec!["ortd".to_string()]).context("cert params")?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(SERVERPK_OID_U64, server_pk.clone()));
    let cert = params.self_signed(&key_pair).context("self-sign cert")?;

    std::fs::write(args.out.join(CERT_FILE), cert.der().as_ref()).context("write cert.der")?;
    write_key(&args.out.join("cert_signing.key"), key_pair.serialize_der().as_slice())?;

    println!("wrote certificate to {}", args.out.join(CERT_FILE).display());
    println!("server_pk (bound in cert): {}", hex(&server_pk));
    Ok(())
}

fn load_server_config(args: &RunArgs) -> Result<ServerConfig<V1>> {
    let kem_secret = match &args.cert {
        Some(dir) => {
            let seed = read_key(&dir.join(KEM_KEY_FILE))
                .with_context(|| "load server KEM key (run `ortd gen-key` first)")?;
            V1::kem_secret_from_bytes(&seed).context("decode server KEM key")?
        }
        None => {
            tracing::warn!("no --cert dir given; generating an ephemeral KEM key for this run");
            V1::kem_generate()
        }
    };
    let server_pk = V1::kem_public(&kem_secret);
    tracing::info!(server_pk = %hex(&server_pk), "server public key");

    let certificate = args
        .cert
        .as_ref()
        .map(|d| d.join(CERT_FILE))
        .filter(|p| p.exists())
        .map(std::fs::read)
        .transpose()
        .context("reading certificate")?
        .unwrap_or_default();

    Ok(ServerConfig {
        kem_secret,
        server_pk,
        certificate,
        window_ms: args.window_ms,
        skew_ms: args.skew_ms,
    })
}

async fn run(args: RunArgs) -> Result<()> {
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

    // Allow the bare form `ortd --listen ... --target ...` (no subcommand) by
    // defaulting to `run` when the first argument looks like an option.
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

    let cli = Cli::parse_from(argv);
    match cli.command {
        Commands::GenKey(args) => gen_key(args),
        Commands::GenCert(args) => gen_cert(args),
        Commands::Run(args) => run(args).await,
    }
}
