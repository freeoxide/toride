//! Hardened `sites-enabled` symlink primitives.
//!
//! Single implementation shared by [`crate::config::ConfigManager`] and
//! [`crate::nginx::NginxManager`], so neither ships a weaker duplicate and
//! neither feature needs to imply the other.

use crate::error::{Error, Result};
use crate::paths::ProxyPaths;
use crate::validate::validate_site_domain;

/// Enable a site by creating a `sites-enabled` symlink.
///
/// `domain` is validated as a single, safe path segment before it is joined
/// onto the sites directory, so traversal-shaped inputs (`..`, absolute
/// paths, nested segments) cannot target arbitrary files. The symlink is
/// created at a temp name and atomically renamed into place, which closes
/// the TOCTOU window of a `symlink`-after-`remove_file` sequence and
/// replaces a pre-existing dangling link instead of failing `EEXIST`.
///
/// # Errors
///
/// Returns [`Error::Validation`] if `domain` is not a safe segment,
/// [`Error::NotFound`] if the source config is missing, or [`Error::Io`] if
/// the symlink cannot be created.
pub(crate) fn enable_site(paths: &ProxyPaths, domain: &str) -> Result<()> {
    validate_site_domain(domain)?;

    let source = paths.nginx_site_path(domain);
    let link = paths.nginx_enabled_path(domain);

    if !source.exists() {
        return Err(Error::NotFound(format!(
            "site config not found: {}",
            source.display()
        )));
    }
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // `sites-enabled` symlinking is a Unix web-server deployment convention;
    // other targets have no equivalent deployment layout, so the operation
    // fails with a clear error instead of pretending to succeed (and the
    // Windows symlink API needs privileges anyway).
    #[cfg(unix)]
    {
        let link_parent = link.parent().unwrap_or(std::path::Path::new("."));
        let tmp_link = link_parent.join(format!(
            ".{}.toride-tmp",
            link.file_name()
                .map_or_else(|| domain.to_string(), |f| f.to_string_lossy().into_owned())
        ));
        // Clean up any stale temp link from a previous crashed attempt, then
        // ignore the (likely) not-found error.
        let _ = std::fs::remove_file(&tmp_link);

        std::os::unix::fs::symlink(&source, &tmp_link)?;
        // Atomic publish. Overwrites an existing link on Unix.
        std::fs::rename(&tmp_link, &link).inspect_err(|_| {
            // Best-effort cleanup of the temp link if the rename failed, so we
            // don't leave an orphaned symlink behind.
            let _ = std::fs::remove_file(&tmp_link);
        })?;

        tracing::info!("enabled site {domain}");
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (source, link);
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "cannot enable site {domain}: sites-enabled symlinks are only supported on Unix"
            ),
        )))
    }
}

/// Disable a site by removing its `sites-enabled` symlink.
///
/// `domain` is validated as a single, safe path segment before joining onto
/// the sites directory, so traversal-shaped inputs cannot delete arbitrary
/// files via the `remove_file` call. The link is detected with
/// `symlink_metadata`, which does not follow the link, so a dangling link
/// (target removed) is still disabled. No-op (returns `Ok`) if the symlink
/// does not exist.
///
/// # Errors
///
/// Returns [`Error::Validation`] if `domain` is not a safe segment, or
/// [`Error::Io`] if the symlink exists but cannot be removed.
pub(crate) fn disable_site(paths: &ProxyPaths, domain: &str) -> Result<()> {
    validate_site_domain(domain)?;

    let link = paths.nginx_enabled_path(domain);
    if link.symlink_metadata().is_ok() {
        std::fs::remove_file(&link)?;
        tracing::info!("disabled site {domain}");
    }
    Ok(())
}
