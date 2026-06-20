//! End-to-end transparency test: boot an echo backend, an `ortd` and an `ortc`,
//! push bytes through a plain TCP client and assert byte-identical echo across
//! the first (1-RTT) and subsequent (0-RTT) connections, for both suites.

use ort_core::handshake::{ClientConfig, ServerConfig, SuiteKey};
use ort_core::suite::agile::{ServerKemKey, SigIdentity};
use ort_core::suite::SuiteId;
use ort_net::{run_client, run_server, ClientParams, ServerVerifier};

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

fn make_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

async fn echo_once(ortc_addr: std::net::SocketAddr, payload: &[u8]) {
    let sock = TcpStream::connect(ortc_addr).await.unwrap();
    sock.set_nodelay(true).unwrap();
    let (mut r, mut w) = sock.into_split();
    let p = payload.to_vec();
    let send = tokio::spawn(async move {
        w.write_all(&p).await.unwrap();
        w.flush().await.unwrap();
        w
    });
    let mut got = vec![0u8; payload.len()];
    r.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "echo mismatch");
    let _w = send.await.unwrap();
}

async fn boot(
    server_suites: &[SuiteId],
    sig_alg: SuiteId,
    kem_suites: Vec<SuiteId>,
) -> std::net::SocketAddr {
    let echo_addr = spawn_echo().await;

    let suites = server_suites
        .iter()
        .map(|id| SuiteKey {
            key: ServerKemKey::generate(*id),
            certificate: vec![],
        })
        .collect();
    let scfg = Arc::new(ServerConfig {
        suites,
        window_ms: 2000,
        skew_ms: 1000,
    });
    let ortd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ortd_addr = ortd_listener.local_addr().unwrap();
    tokio::spawn(run_server(ortd_listener, echo_addr, scfg));

    let cfg = ClientConfig::new(SigIdentity::generate(sig_alg));
    let params = Arc::new(ClientParams {
        cfg,
        kem_suites,
        verifier: ServerVerifier::TrustOnFirstUse,
        force_1rtt: false,
    });
    let ortc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ortc_addr = ortc_listener.local_addr().unwrap();
    tokio::spawn(run_client(ortc_listener, ortd_addr, params));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    ortc_addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_v1_1rtt_then_0rtt() {
    let ortc = boot(
        &[SuiteId::V1MlKem768MlDsa65],
        SuiteId::V1MlKem768MlDsa65,
        vec![SuiteId::V1MlKem768MlDsa65],
    )
    .await;
    echo_once(ortc, &make_payload(13)).await; // 1-RTT
    let big = make_payload(256 * 1024);
    echo_once(ortc, &big).await; // 0-RTT
    echo_once(ortc, &big).await; // 0-RTT again
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_v2_classical() {
    let ortc = boot(
        &[SuiteId::V2X25519Ed25519],
        SuiteId::V2X25519Ed25519,
        vec![SuiteId::V2X25519Ed25519],
    )
    .await;
    echo_once(ortc, &make_payload(64)).await;
    echo_once(ortc, &make_payload(100_000)).await; // 0-RTT
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_negotiation_server_both_client_prefers_v1() {
    // Server supports both; client signs with Ed25519 (v2) but offers v1 then v2.
    let ortc = boot(
        &[SuiteId::V2X25519Ed25519, SuiteId::V1MlKem768MlDsa65],
        SuiteId::V2X25519Ed25519,
        vec![SuiteId::V1MlKem768MlDsa65, SuiteId::V2X25519Ed25519],
    )
    .await;
    echo_once(ortc, &make_payload(1000)).await;
    echo_once(ortc, &make_payload(50_000)).await;
}
