//! Accept loops that tie the session driver and forwarder into runnable
//! client/server daemons, shared by the binaries and the integration tests.

use crate::cert::ServerVerifier;
use crate::forward::forward;
use crate::replay::ConcurrentStrikeCache;
use crate::session::{client_0rtt, client_1rtt};

use ort_core::handshake::{ClientConfig, ServerConfig};
use ort_core::suite::SuiteId;
use ort_core::time::SystemClock;

use std::collections::HashMap;
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
                        if let Err(e) = forward(tstream, out.conn, None, out.early_data).await {
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

#[derive(Default)]
struct Cache {
    observed_ip: Option<[u8; 16]>,
    pks: HashMap<SuiteId, Vec<u8>>,
}

/// Run the `ortc` client: accept local app connections and tunnel each to the
/// remote `ortd` at `target`. After first contact it caches the server key(s)
/// and the server-observed source IP so later connections use 0-RTT.
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

async fn handle_client_conn(
    app_sock: TcpStream,
    target: SocketAddr,
    params: &ClientParams,
    cache: &Arc<Mutex<Cache>>,
) -> crate::Result<()> {
    let clock = SystemClock;

    // Decide 0-RTT vs 1-RTT from the cache.
    let zero_rtt = if params.force_1rtt {
        None
    } else {
        let c = cache.lock().await;
        c.observed_ip.map(|ip| {
            let offers: Vec<(SuiteId, Vec<u8>)> = params
                .kem_suites
                .iter()
                .filter_map(|s| c.pks.get(s).map(|pk| (*s, pk.clone())))
                .collect();
            (ip, offers)
        })
    };

    if let Some((observed_ip, offers)) = zero_rtt {
        if !offers.is_empty() {
            let ortd = TcpStream::connect(target).await?;
            let outcome = client_0rtt(ortd, &params.cfg, &offers, observed_ip, &clock, b"").await?;
            if let Err(e) = forward(app_sock, outcome.conn, outcome.expect_ack, Vec::new()).await {
                // Likely a stale cache (e.g. NAT rebinding); drop it so the next
                // connection re-learns via 1-RTT.
                cache.lock().await.observed_ip = None;
                return Err(e);
            }
            return Ok(());
        }
    }

    // 1-RTT.
    let ortd = TcpStream::connect(target).await?;
    let pinned = {
        let c = cache.lock().await;
        params.kem_suites.iter().find_map(|s| c.pks.get(s).cloned())
    };
    let outcome = client_1rtt(
        ortd,
        &params.cfg,
        &params.kem_suites,
        &params.verifier,
        pinned.as_deref(),
        &clock,
        b"",
    )
    .await?;
    if let Some(learned) = &outcome.learned {
        let mut c = cache.lock().await;
        c.observed_ip = Some(learned.observed_ip);
        c.pks
            .insert(learned.accepted_suite, learned.server_pk.clone());
    }
    forward(app_sock, outcome.conn, outcome.expect_ack, Vec::new()).await
}
