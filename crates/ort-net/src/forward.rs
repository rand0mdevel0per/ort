//! Transparent bidirectional forwarding between a plaintext TCP stream and an
//! established ORT tunnel connection.

use crate::error::Result;
use crate::session::OrtConn;

use ort_proto::Frame;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// Plaintext read/copy chunk size.
const CHUNK: usize = 16 * 1024;

fn invalid(e: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

/// Pump bytes between `plain` (the local app or backend target) and the ORT
/// tunnel `conn`, encrypting/decrypting via the record layer.
///
/// - `expect_ack`: for client 0-RTT, the expected ServerAck key-confirmation
///   hash; the first inbound frame must be that ack.
/// - `early_to_plain`: decrypted early data (server side) to flush to `plain`
///   before pumping.
pub async fn forward(
    plain: TcpStream,
    conn: OrtConn,
    expect_ack: Option<[u8; 64]>,
    early_to_plain: Vec<u8>,
) -> Result<()> {
    let _ = plain.set_nodelay(true);
    let OrtConn { mut reader, mut writer, record, role } = conn;
    let send_dir = role.send_dir();
    let recv_dir = role.recv_dir();

    let (mut pr, mut pw) = plain.into_split();
    if !early_to_plain.is_empty() {
        pw.write_all(&early_to_plain).await?;
    }

    let record = Arc::new(Mutex::new(record));

    // plain -> tunnel
    let up = {
        let record = record.clone();
        async move {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = pr.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let ct = {
                    let mut rec = record.lock().await;
                    rec.seal(send_dir, &buf[..n])
                };
                let frame = Frame::DataRecord { dir: send_dir as u8, ciphertext: ct };
                writer.write_frame(&frame.encode()).await?;
            }
            let _ = writer.write_frame(&Frame::Close.encode()).await;
            let _ = writer.shutdown().await;
            Ok::<(), crate::error::OrtError>(())
        }
    };

    // tunnel -> plain
    let down = {
        let record = record.clone();
        async move {
            if let Some(expected) = expect_ack {
                match reader.read_frame().await? {
                    None => return Ok(()),
                    Some(body) => match Frame::decode(&body)? {
                        Frame::ServerAck { ek_hash } => {
                            if ek_hash != expected {
                                return Err(crate::error::OrtError::KeyConfirmation);
                            }
                        }
                        _ => return Err(crate::error::OrtError::Unexpected("expected ServerAck")),
                    },
                }
            }
            loop {
                match reader.read_frame().await? {
                    None => break,
                    Some(body) => match Frame::decode(&body)? {
                        Frame::DataRecord { ciphertext, .. } => {
                            let pt = {
                                let mut rec = record.lock().await;
                                rec.open(recv_dir, &ciphertext).map_err(invalid)?
                            };
                            pw.write_all(&pt).await?;
                        }
                        Frame::Close => break,
                        _ => return Err(crate::error::OrtError::Unexpected("expected DataRecord")),
                    },
                }
            }
            let _ = pw.shutdown().await;
            Ok::<(), crate::error::OrtError>(())
        }
    };

    tokio::try_join!(up, down)?;
    Ok(())
}
