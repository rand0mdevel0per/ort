//! Accept loops that tie the session driver and forwarder into runnable
//! client/server daemons, shared by the binaries and the integration tests.

use crate::cert::ServerVerifier;
use crate::forward::forward;
use crate::session::{client_open, server_accept};

use ort_core::handshake::{ClientConfig, ServerConfig};
use ort_core::replay::StrikeCache;
use ort_core::suite::v1::V1;
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
    scfg: Arc<ServerConfig<V1>>,
) -> std::io::Result<()> {
    let strike = Arc::new(Mutex::new(StrikeCache::new(scfg.window_ms)));
    loop {
        let (sock, peer) = listener.accept().await?;
        let scfg = scfg.clone();
        let strike = strike.clone();
        tokio::spawn(async move {
            let peer_ip = ip_to_bytes(peer.ip());
            let clock = SystemClock;
            match server_accept(sock, peer_ip, &scfg, &strike, &clock).await {
                Ok(out) => match TcpStream::connect(target).await {
                    Ok(tstream) => {
                        if let Err(e) = forward(tstream, out.conn, None, out.early_data).await {
                            tracing::debug!(error = %e, "server forward ended");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, %target, "connect to target failed"),
                },
                Err(e) => tracing::debug!(error = %e, "server handshake failed"),
            }
        });
    }
}

/// Run the `ortc` client: accept local app connections and tunnel each to the
/// remote `ortd` at `target`. Caches the server public key after first contact
/// so subsequent connections use 0-RTT.
pub async fn run_client(
    listener: TcpListener,
    target: SocketAddr,
    ccfg: Arc<ClientConfig<V1>>,
    verifier: ServerVerifier,
    force_1rtt: bool,
) -> std::io::Result<()> {
    let pin: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    loop {
        let (app_sock, _) = listener.accept().await?;
        let ccfg = ccfg.clone();
        let verifier = verifier.clone();
        let pin = pin.clone();
        tokio::spawn(async move {
            let ortd = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, %target, "connect to ortd failed");
                    return;
                }
            };
            let src_ip = match ortd.local_addr() {
                Ok(a) => ip_to_bytes(a.ip()),
                Err(_) => [0u8; 16],
            };
            let cached = pin.lock().await.clone();
            let clock = SystemClock;
            match client_open(ortd, &ccfg, src_ip, cached, force_1rtt, &verifier, &clock, b"").await
            {
                Ok(outcome) => {
                    {
                        let mut p = pin.lock().await;
                        if p.is_none() {
                            *p = Some(outcome.server_pk.clone());
                        }
                    }
                    if let Err(e) =
                        forward(app_sock, outcome.conn, outcome.expect_ack, Vec::new()).await
                    {
                        tracing::debug!(error = %e, "client forward ended");
                    }
                }
                Err(e) => tracing::debug!(error = %e, "client handshake failed"),
            }
        });
    }
}
