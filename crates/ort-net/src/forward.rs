//! Transparent bidirectional forwarding between a plaintext TCP stream and an
//! established ORT tunnel connection.
//!
//! The record layer is split into independent send/receive halves so the two
//! directions run in separate tasks with no shared lock (true full duplex).
//! When either direction ends, the other is aborted, so a half-close on one
//! side always tears the whole tunnel down (no `try_join!` deadlock).

use crate::error::{OrtError, Result};
use crate::session::{OrtConn, Role};

use ort_proto::Frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Plaintext read/copy chunk size.
const CHUNK: usize = 16 * 1024;

fn invalid(e: ort_core::Error) -> OrtError {
    OrtError::Core(e)
}

/// Pump bytes between `plain` (the local app or backend target) and the ORT
/// tunnel `conn`. The handshake (including any ServerAck key confirmation) is
/// already complete by the time this is called.
///
/// `early_to_plain` is decrypted early data (server side) to flush before pumping.
pub async fn forward(plain: TcpStream, conn: OrtConn, early_to_plain: Vec<u8>) -> Result<()> {
    let _ = plain.set_nodelay(true);
    let OrtConn { reader, mut writer, record, role } = conn;
    let send_from_server = matches!(role, Role::Server);
    let expect_from_server = !send_from_server;

    let (mut sender, mut receiver) = record.split(role.send_dir());
    let (mut pr, mut pw) = plain.into_split();
    if !early_to_plain.is_empty() {
        pw.write_all(&early_to_plain).await?;
    }

    // plain -> tunnel
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = pr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let ct = sender.seal(&buf[..n]);
            let frame = Frame::DataRecord { from_server: send_from_server, ciphertext: ct };
            writer.write_frame(&frame.encode()).await?;
        }
        let _ = writer.write_frame(&Frame::Close.encode()).await;
        let _ = writer.shutdown().await;
        Ok::<(), OrtError>(())
    });

    // tunnel -> plain
    let mut reader = reader;
    let down = tokio::spawn(async move {
        loop {
            match reader.read_frame().await? {
                None => break,
                Some(body) => match Frame::decode(&body)? {
                    Frame::DataRecord { from_server, ciphertext } => {
                        if from_server != expect_from_server {
                            return Err(OrtError::Unexpected("wrong record direction"));
                        }
                        let pt = receiver.open(&ciphertext).map_err(invalid)?;
                        pw.write_all(&pt).await?;
                    }
                    Frame::Close => break,
                    _ => return Err(OrtError::Unexpected("expected DataRecord")),
                },
            }
        }
        let _ = pw.shutdown().await;
        Ok::<(), OrtError>(())
    });

    // Whichever direction ends first aborts the other (no deadlock, no leak).
    let up_abort = up.abort_handle();
    let down_abort = down.abort_handle();
    tokio::select! {
        r = up => { down_abort.abort(); flatten(r) }
        r = down => { up_abort.abort(); flatten(r) }
    }
}

fn flatten(join: std::result::Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match join {
        Ok(inner) => inner,
        Err(e) if e.is_cancelled() => Ok(()),
        Err(_) => Ok(()),
    }
}
