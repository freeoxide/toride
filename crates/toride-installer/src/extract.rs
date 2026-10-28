//! Artifact extraction.
//!
//! A [`Tool`](crate::Tool) publishes either a single [`Binary`](crate::ArtifactKind::Binary)
//! file (placed verbatim) or a compressed [`Tarball`]
//! (decompressed with gzip or xz, then the target entry is located and
//! copied out). Both kinds are implemented here so the framework is
//! genuinely general, even though the only wired tool (mise) currently
//! uses `Binary`.

use std::io::Read;

use crate::error::{Error, Result};
use crate::tool::{ArtifactKind, Tarball};

/// Locate and return the executable bytes from a downloaded artifact.
///
/// For [`ArtifactKind::Binary`] the input `bytes` are returned unchanged
/// (they ARE the executable). For [`ArtifactKind::Tarball`] the archive is
/// decompressed and the entry named `bin_path` is located and read into a
/// `Vec<u8>`.
///
/// # Errors
///
/// - [`Error::Archive`] if the archive cannot be read/decompressed.
/// - [`Error::EntryNotFound`] if `bin_path` is not present in the archive.
pub fn extract_executable(
    bytes: &[u8],
    kind: ArtifactKind,
    tool: &str,
    bin_path: Option<&str>,
) -> Result<Vec<u8>> {
    match kind {
        ArtifactKind::Binary => Ok(bytes.to_vec()),
        ArtifactKind::Tarball(compression) => {
            let bin_path = bin_path.ok_or_else(|| Error::MissingConfig {
                tool: tool.to_owned(),
                field: "bin_path".into(),
            })?;
            extract_tar_entry(bytes, compression, tool, bin_path)
        }
    }
}

/// Read the file at `bin_path` out of an in-memory tar archive.
///
/// A multi-component `bin_path` (e.g. `bin/mise`) must match the entry's
/// full path exactly (both sides with a leading `./` stripped), so two
/// same-basename entries in different directories cannot collide. A
/// single-component `bin_path` keeps the bare-filename fallback (entries
/// arrive prefixed, e.g. `mise-1.0/mise`); the first file entry whose final
/// component matches wins.
fn extract_tar_entry(
    bytes: &[u8],
    compression: Tarball,
    tool: &str,
    bin_path: &str,
) -> Result<Vec<u8>> {
    // Wrap the raw bytes in a decompressor and feed the result to `tar`.
    let decoded: Box<dyn Read> = match compression {
        Tarball::Gz => Box::new(flate2::read::GzDecoder::new(bytes)),
        Tarball::Xz => Box::new(xz2::read::XzDecoder::new(bytes)),
    };

    let mut archive = tar::Archive::new(decoded);

    let wanted_path = bin_path.strip_prefix("./").unwrap_or(bin_path);
    let single_component = std::path::Path::new(wanted_path)
        .components()
        .nth(1)
        .is_none();
    let wanted_name = std::path::Path::new(wanted_path)
        .file_name()
        .map(std::ffi::OsStr::to_string_lossy)
        .unwrap_or_default()
        .into_owned();

    let mut basename_hit: Option<Vec<u8>> = None;

    for entry in archive.entries().map_err(|e| Error::Archive {
        kind: compression.extension(),
        source: e,
    })? {
        let mut entry = entry.map_err(|e| Error::Archive {
            kind: compression.extension(),
            source: e,
        })?;

        let path = entry.path().map_err(|e| Error::Archive {
            kind: compression.extension(),
            source: e,
        })?;

        if !entry.header().entry_type().is_file() {
            continue;
        }

        let entry_path = path.to_string_lossy();
        let entry_path = entry_path.strip_prefix("./").unwrap_or(&entry_path);

        if entry_path == wanted_path {
            return read_entry_bytes(&mut entry, compression);
        }
        if single_component
            && basename_hit.is_none()
            && path
                .file_name()
                .is_some_and(|name| name.to_string_lossy() == wanted_name)
        {
            basename_hit = Some(read_entry_bytes(&mut entry, compression)?);
        }
    }

    basename_hit.ok_or_else(|| Error::EntryNotFound {
        tool: tool.to_owned(),
        bin_path: bin_path.to_owned(),
    })
}

/// Read one file entry into a `Vec<u8>`.
///
/// The tar-header declared size is not trusted for the allocation: a
/// hostile or malformed header could claim an enormous entry size and force
/// a huge `Vec` reservation (OOM). The reservation is bounded by the same
/// ceiling the download stage enforces ([`crate::installer::DEFAULT_MAX_BYTES`]);
/// an absent or implausibly large declared size reserves nothing and
/// `read_to_end` grows the buffer as bytes arrive.
fn read_entry_bytes<R: Read>(entry: &mut tar::Entry<R>, compression: Tarball) -> Result<Vec<u8>> {
    let declared = entry.size();
    let declared_usize = usize::try_from(declared).unwrap_or(0);
    let cap = declared_usize
        .min(usize::try_from(crate::installer::DEFAULT_MAX_BYTES).unwrap_or(usize::MAX));
    let mut buf = Vec::with_capacity(cap);
    entry.read_to_end(&mut buf).map_err(|e| Error::Archive {
        kind: compression.extension(),
        source: e,
    })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build an in-memory `.tar.gz` containing `files` and return its bytes.
    fn make_targz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *name, std::io::Cursor::new(*data))
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap()
    }

    /// Build an in-memory `.tar.xz` containing `files` and return its bytes.
    fn make_tarxz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (name, data) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *name, std::io::Cursor::new(*data))
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar_buf).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn binary_kind_returns_bytes_unchanged() {
        let payload = b"\x7fELF(fake)";
        let out = extract_executable(payload, ArtifactKind::Binary, "demo", None).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn tarball_gz_extracts_named_entry() {
        let archive = make_targz(&[
            ("README.md", b"docs"),
            ("bin/mise", b"BINARY-CONTENTS"),
            ("LICENSE", b"mit"),
        ]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("bin/mise"),
        )
        .unwrap();
        assert_eq!(out, b"BINARY-CONTENTS");
    }

    #[test]
    fn tarball_gz_matches_on_bare_filename() {
        let archive = make_targz(&[("mise-1.0/mise", b"X")]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("mise"),
        )
        .unwrap();
        assert_eq!(out, b"X");
    }

    #[test]
    fn tarball_full_path_match_wins_over_earlier_same_basename() {
        // bin_path has multiple components: only the exact full-path entry
        // may match, so an earlier "other/mise" cannot shadow "bin/mise".
        let archive = make_targz(&[("other/mise", b"WRONG"), ("bin/mise", b"RIGHT")]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("bin/mise"),
        )
        .unwrap();
        assert_eq!(out, b"RIGHT");
    }

    #[test]
    fn tarball_multi_component_bin_path_needs_exact_match() {
        // A same-basename entry in a different directory does not satisfy a
        // multi-component bin_path.
        let archive = make_targz(&[("other/mise", b"WRONG")]);
        let err = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("bin/mise"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::EntryNotFound { .. }));
    }

    #[test]
    fn tarball_strips_dot_slash_from_both_sides() {
        let archive = make_targz(&[("./bin/mise", b"OK")]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("bin/mise"),
        )
        .unwrap();
        assert_eq!(out, b"OK");

        let archive = make_targz(&[("bin/mise", b"OK2")]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("./bin/mise"),
        )
        .unwrap();
        assert_eq!(out, b"OK2");
    }

    #[test]
    fn tarball_xz_extracts_named_entry() {
        let archive = make_tarxz(&[("node", b"NODE-BIN")]);
        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Xz),
            "node",
            Some("node"),
        )
        .unwrap();
        assert_eq!(out, b"NODE-BIN");
    }

    #[test]
    fn tarball_missing_entry_is_an_error() {
        let archive = make_targz(&[("other", b"x")]);
        let err = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("mise"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::EntryNotFound { .. }));
    }

    #[test]
    fn tarball_garbage_is_an_archive_error() {
        let err = extract_executable(
            b"not a tarball",
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("mise"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Archive { .. }));
    }

    #[test]
    fn tarball_without_bin_path_is_missing_config() {
        let archive = make_targz(&[("mise", b"x")]);
        let err = extract_executable(&archive, ArtifactKind::Tarball(Tarball::Gz), "mise", None)
            .unwrap_err();
        assert!(matches!(err, Error::MissingConfig { .. }));
    }

    #[test]
    fn tarball_skips_directory_entry_sharing_name() {
        // An entry named "mise" but typed as a directory should not match;
        // the real file "mise" elsewhere should win.
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);

            // directory entry named "mise"
            let dir_data: &[u8] = &[];
            let mut dir_header = tar::Header::new_gnu();
            dir_header.set_size(0);
            dir_header.set_mode(0o755);
            dir_header.set_entry_type(tar::EntryType::Directory);
            dir_header.set_cksum();
            builder
                .append_data(&mut dir_header, "mise", std::io::Cursor::new(dir_data))
                .unwrap();

            // real file named "mise"
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(4);
            file_header.set_mode(0o755);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "real/mise", std::io::Cursor::new(b"REAL"))
                .unwrap();

            builder.finish().unwrap();
        }
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_buf).unwrap();
        let archive = encoder.finish().unwrap();

        let out = extract_executable(
            &archive,
            ArtifactKind::Tarball(Tarball::Gz),
            "mise",
            Some("mise"),
        )
        .unwrap();
        assert_eq!(out, b"REAL");
    }
}
