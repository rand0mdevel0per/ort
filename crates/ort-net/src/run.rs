//! Accept loops that tie the session driver and forwarder into runnable
//! client/server daemons, shared by the binaries and the integration tests.

use crate::cert::ServerVerifier;
use crate::forward::forward;
use crate::replay::ConcurrentStrikeCache;
use crate::session::{client_0rtt, client_1rtt};

use ort_core::handshake::{ClientConfig, ServerConfig};
use ort_core::suite::SuiteId;
use ort_core::time::SystemClock;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Convert an IP to its canonical 16-byte form (IPv4 → IPv4-mapped IPv6).
pub fn ip_to_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Run the `ortd` server: accept ORT connections, terminate the tunnel and
/// forward plaintext to `target`. Never returns under normal operation.
pub async fn run_server(
    listener: TcpListener,
    target: SocketAddr,
    scfg: Arc<ServerConfig>,
) -> std::io::Result<()> {
    let guard = Arc::new(ConcurrentStrikeCache::new(scfg.window_ms));
    loop {
        let (sock, peer) = listener.accept().await?;
        let scfg = scfg.clone();
        let guard = guard.clone();
        tokio::spawn(async move {
            let peer_ip = ip_to_bytes(peer.ip());
            let clock = SystemClock;
            match crate::session::server_accept(sock, peer_ip, &scfg, &*guard, &clock).await {
                Ok(out) => match TcpStream::connect(target).await {
                    Ok(tstream) => {
                        if let Err(e) = forward(tstream, out.conn, out.early_data).await {
                            tracing::debug!(error = %e, "server forward ended");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, %target, "connect to target failed"),
                },
                Err(e) => tracing::debug!(error = %e, "server handshake rejected/failed"),
            }
        });
    }
}

/// Client configuration for the accept loop.
pub struct ClientParams {
    /// The client signing identity + cached public key.
    pub cfg: ClientConfig,
    /// KEM suites the client supports, in preference order.
    pub kem_suites: Vec<SuiteId>,
    /// Server verification policy.
    pub verifier: ServerVerifier,
    /// Force 1-RTT (disable 0-RTT resumption).
    pub force_1rtt: bool,
}

/// Cached state from the last successful 1-RTT: the server-observed source IP
/// and the single suite the server accepted (with its public key). 0-RTT
/// resumes with exactly this suite (the only one the client holds a key for).
#[derive(Default)]
struct Cache {
    observed_ip: Option<[u8; 16]>,
    primary: Option<(SuiteId, Vec<u8>, Vec<u8>)>, // (suite, server_pk, certificate)
}

/// Run the `ortc` client: accept local app connections and tunnel each to the
/// remote `ortd`. After first contact it records the accepted suite + server
/// key so later connections use 0-RTT, falling back to 1-RTT if the server no
/// longer accepts that suite.
pub async fn run_client(
    listener: TcpListener,
    target: SocketAddr,
    params: Arc<ClientParams>,
) -> std::io::Result<()> {
    let cache: Arc<Mutex<Cache>> = Arc::new(Mutex::new(Cache::default()));
    loop {
        let (app_sock, _) = listener.accept().await?;
        let params = params.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client_conn(app_sock, target, &params, &cache).await {
                tracing::debug!(error = %e, "client connection ended");
            }
        });
    }
}

/// Is this 0-RTT failure recoverable by retrying the same app connection as 1-RTT?
fn is_zero_rtt_fallback(e: &crate::OrtError) -> bool {
    matches!(
        e,
        crate::OrtError::Rejected(_)
            | crate::OrtError::UnexpectedSuite(_)
            | crate::OrtError::KeyConfirmation
            | crate::OrtError::EarlyClose
            | crate::OrtError::PinMismatch
            | crate::OrtError::Cert(_)
            | crate::OrtError::Core(_)
    )
}

async fn handle_client_conn(
    app_sock: TcpStream,
    target: SocketAddr,
    params: &ClientParams,
    cache: &Arc<Mutex<Cache>>,
) -> crate::Result<()> {
    let clock = SystemClock;

    // Try 0-RTT if we have a cached suite the client still supports.
    let zero_rtt = if params.force_1rtt {
        None
    } else {
        let c = cache.lock().await;
        match (c.observed_ip, &c.primary) {
            (Some(ip), Some((suite, pk, cert))) if params.kem_suites.contains(suite) => {
                Some((ip, *suite, pk.clone(), cert.clone()))
            }
            _ => None,
        }
    };

    if let Some((observed_ip, suite, pk, cert)) = zero_rtt {
        let ortd = TcpStream::connect(target).await?;
        match client_0rtt(ortd, &params.cfg, suite, &pk, &cert, observed_ip, &clock, b"").await {
            Ok(outcome) => return forward(app_sock, outcome.conn, Vec::new()).await,
            Err(e) if is_zero_rtt_fallback(&e) => {
                tracing::debug!(error = %e, "0-RTT failed; falling back to 1-RTT");
                cache.lock().await.primary = None; // re-learn via 1-RTT
            }
            Err(e) => return Err(e),
        }
    }

    // 1-RTT (first contact or 0-RTT fallback). `app_sock` is untouched so the
    // fallback loses no application data.
    let ortd = TcpStream::connect(target).await?;
    let outcome = client_1rtt(
        ortd,
        &params.cfg,
        &params.kem_suites,
        &params.verifier,
        None,
        &clock,
        b"",
    )
    .await?;
    if let Some(learned) = &outcome.learned {
        let mut c = cache.lock().await;
        c.observed_ip = Some(learned.observed_ip);
        c.primary = Some((learned.accepted_suite, learned.server_pk.clone(), learned.certificate.clone()));
    }
    forward(app_sock, outcome.conn, Vec::new()).await
}
