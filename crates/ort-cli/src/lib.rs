//! Shared plumbing for the ORT binaries: logging, key file IO.

use anyhow::{Context, Result};
use std::path::Path;
use zeroize::Zeroizing;

/// Initialize tracing from the `RUST_LOG` env (default `info`).
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

/// Read a raw key file into zeroizing memory.
pub fn read_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading key {}", path.display()))?;
    Ok(Zeroizing::new(bytes))
}

/// Write a raw key file with `0600` permissions where supported.
pub fn write_key(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, bytes).with_context(|| format!("writing key {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Hex-encode bytes (lowercase).
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
