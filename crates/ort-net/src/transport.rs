//! Length-prefixed frame transport over any async byte stream.

use ort_proto::{encode_framed, parse_len, ProtoError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads length-prefixed frame bodies from an async source.
pub struct FramedReader<R> {
    inner: R,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    /// Wrap a reader.
    pub fn new(inner: R) -> Self {
        FramedReader { inner }
    }

    /// Fill `buf` completely. Returns `Ok(false)` *only* on a clean
    /// end-of-stream at a frame boundary (zero bytes read before any data);
    /// a partial read followed by EOF is a protocol error.
    async fn read_full(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.inner.read(&mut buf[filled..]).await?;
            if n == 0 {
                if filled == 0 {
                    return Ok(false); // clean EOF at boundary
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-frame",
                ));
            }
            filled += n;
        }
        Ok(true)
    }

    /// Read the next frame body, or `None` on a clean end-of-stream.
    pub async fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        if !self.read_full(&mut len_buf).await? {
            return Ok(None);
        }
        let n = parse_len(len_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut body = vec![0u8; n];
        if !self.read_full(&mut body).await? {
            // Length prefix consumed but no body bytes: truncated frame.
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                ProtoError::Truncated,
            ));
        }
        Ok(Some(body))
    }
}

/// Writes length-prefixed frame bodies to an async sink.
pub struct FramedWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Wrap a writer.
    pub fn new(inner: W) -> Self {
        FramedWriter { inner }
    }

    /// Write a frame body with its length prefix and flush.
    pub async fn write_frame(&mut self, body: &[u8]) -> std::io::Result<()> {
        let framed = encode_framed(body)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.inner.write_all(&framed).await?;
        self.inner.flush().await
    }

    /// Shut down the underlying writer.
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.inner.shutdown().await
    }
}
