//! End-to-end transparency test: boot an echo backend, an `ortd` and an `ortc`,
//! push bytes through a plain TCP client and assert byte-identical echo across
//! the first (1-RTT) and subsequent (0-RTT) connections.

use ort_core::handshake::{ClientConfig, ServerConfig};
use ort_core::suite::v1::V1;
use ort_core::suite::CipherSuite;
use ort_net::{run_client, run_server, ServerVerifier};

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A trivial echo server: copies its input back to the caller.
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
    (0..len).map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8).collect()
}

/// Open a connection, write `payload`, read back exactly `payload.len()` bytes
/// and assert equality.
async fn echo_once(ortc_addr: std::net::SocketAddr, payload: &[u8]) {
    let sock = TcpStream::connect(ortc_addr).await.unwrap();
    sock.set_nodelay(true).unwrap();
    let (mut r, mut w) = sock.into_split();

    let p = payload.to_vec();
    let send = tokio::spawn(async move {
        w.write_all(&p).await.unwrap();
        w.flush().await.unwrap();
        w // hold open
    });

    let mut got = vec![0u8; payload.len()];
    r.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload, "echo mismatch");

    let _w = send.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn echo_through_ort_tunnel_1rtt_and_0rtt() {
    // 1. echo backend
    let echo_addr = spawn_echo().await;

    // 2. ortd
    let kem_secret = V1::kem_generate();
    let server_pk = V1::kem_public(&kem_secret);
    let scfg = Arc::new(ServerConfig {
        kem_secret,
        server_pk,
        certificate: vec![],
        window_ms: 2000,
        skew_ms: 1000,
    });
    let ortd_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ortd_addr = ortd_listener.local_addr().unwrap();
    tokio::spawn(run_server(ortd_listener, echo_addr, scfg));

    // 3. ortc
    let sig_secret = V1::sig_generate();
    let client_pk = V1::sig_public(&sig_secret);
    let ccfg = Arc::new(ClientConfig { sig_secret, client_pk });
    let ortc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ortc_addr = ortc_listener.local_addr().unwrap();
    tokio::spawn(run_client(
        ortc_listener,
        ortd_addr,
        ccfg,
        ServerVerifier::TrustOnFirstUse,
        false,
    ));

    // small settle
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // First connection: 1-RTT (no cached pk). Then subsequent: 0-RTT.
    let small = make_payload(13);
    echo_once(ortc_addr, &small).await; // 1-RTT

    let big = make_payload(256 * 1024);
    echo_once(ortc_addr, &big).await; // 0-RTT, multi-chunk
    echo_once(ortc_addr, &big).await; // 0-RTT again
}
