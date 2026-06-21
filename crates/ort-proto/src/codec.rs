//! Minimal, explicit binary codec primitives.
//!
//! All integers are big-endian. Variable-length byte fields use a `u32` length
//! prefix (handshake blobs and record payloads can exceed 64 KiB). Every read is
//! bounds-checked; writes assert the field fits a `u32`.

use crate::ProtoError;

/// Append-only big-endian writer over a `Vec<u8>`.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// New empty writer.
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    /// New writer with reserved capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Consume and return the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Write a single byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    /// Write a big-endian u16.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write a big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write a big-endian u64.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write raw fixed-length bytes (no length prefix).
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// Write a `u32`-length-prefixed byte field. Panics only on the impossible
    /// case of a field larger than 4 GiB (asserted, not `debug_assert`).
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        assert!(
            b.len() <= u32::MAX as usize,
            "field length {} exceeds u32",
            b.len()
        );
        self.u32(b.len() as u32);
        self.buf.extend_from_slice(b);
        self
    }
}

/// Bounds-checked big-endian reader over a byte slice.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// New reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.remaining() < n {
            return Err(ProtoError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    /// Read a big-endian u16.
    pub fn u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a big-endian u32.
    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a big-endian u64.
    pub fn u64(&mut self) -> Result<u64, ProtoError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Read `n` raw bytes.
    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        self.take(n)
    }

    /// Read a fixed-size array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtoError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Read a `u32`-length-prefixed byte field. The length is implicitly bounded
    /// by the remaining buffer (which is itself capped by the outer frame size),
    /// so this cannot over-allocate.
    pub fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    /// Ensure the reader is fully consumed (no trailing garbage).
    pub fn expect_end(&self) -> Result<(), ProtoError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtoError::TrailingBytes(self.remaining()))
        }
    }
}
