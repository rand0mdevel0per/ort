//! Length-prefixed frame transport over any async byte stream.

use ort_proto::{encode_framed, parse_len};
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

    /// Read the next frame body, or `None` on a clean end-of-stream.
    pub async fn read_frame(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let mut len_buf = [0u8; 4];
        match self.inner.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let n = parse_len(len_buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut body = vec![0u8; n];
        self.inner.read_exact(&mut body).await?;
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
        let framed = encode_framed(body);
        self.inner.write_all(&framed).await?;
        self.inner.flush().await
    }

    /// Shut down the underlying writer.
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.inner.shutdown().await
    }
}
