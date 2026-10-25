//! Optional debuginfod client, compiled only with the `debuginfod` feature. Fetches a binary or
//! its separate debuginfo by GNU build-id from the servers in `$DEBUGINFOD_URLS`, caching each
//! artifact under the user cache directory so later runs reuse it offline. Every failure (no
//! server configured, a network error, a 404) yields `None`; nothing here panics, and the base
//! build never pulls this module or its HTTP dependency in.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Timeouts that bound a hung server without capping transfer time: a connect deadline and a
/// per-read deadline, so a stalled socket fails fast while a large, steadily streaming debuginfo
/// file is never truncated the way a single global timeout would truncate it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Monotonic per-process counter that makes each download's temp file name unique. Symbolization
/// runs across rayon threads, so two threads can fetch the same artifact at once; without this they
/// would share one temp path and clobber each other.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Which artifact to fetch for a build-id.
#[derive(Clone, Copy)]
pub(crate) enum Artifact {
    /// The executable or shared object itself (debuginfod `/buildid/<id>/executable`).
    Executable,
    /// The separate debuginfo (DWARF) file (debuginfod `/buildid/<id>/debuginfo`).
    Debuginfo,
}

impl Artifact {
    /// The debuginfod URL path segment, also used as the cache file name.
    fn as_str(self) -> &'static str {
        match self {
            Artifact::Executable => "executable",
            Artifact::Debuginfo => "debuginfo",
        }
    }
}

/// Fetch an artifact for `build_id` from the configured debuginfod servers, returning the path to
/// the cached file, or `None` when no server has it (or none are configured). An already-cached
/// artifact is returned without any network request.
pub(crate) fn fetch(build_id: &str, artifact: Artifact) -> Option<PathBuf> {
    let cached = cache_path(build_id, artifact)?;
    if cached.is_file() {
        return Some(cached);
    }
    for server in servers() {
        if download(&server, build_id, artifact, &cached) {
            tracing::debug!(%build_id, artifact = artifact.as_str(), %server, "fetched via debuginfod");
            return Some(cached);
        }
    }
    None
}

/// The debuginfod servers from `$DEBUGINFOD_URLS`, whitespace-separated, in the order listed.
fn servers() -> Vec<String> {
    parse_servers(&std::env::var("DEBUGINFOD_URLS").unwrap_or_default())
}

/// Split a `DEBUGINFOD_URLS` value into servers: whitespace-separated, trailing slashes trimmed.
/// Empty when the value is blank.
fn parse_servers(raw: &str) -> Vec<String> {
    raw.split_whitespace()
        .map(|s| s.trim_end_matches('/').to_string())
        .collect()
}

/// The cache file path for a build-id artifact: `<cache>/coretriage/debuginfod/<id>/<artifact>`.
/// Returns `None` for a non-hex build-id, so a crafted id cannot escape the cache directory.
fn cache_path(build_id: &str, artifact: Artifact) -> Option<PathBuf> {
    if build_id.is_empty() || !build_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(
        cache_root()?
            .join("coretriage")
            .join("debuginfod")
            .join(build_id)
            .join(artifact.as_str()),
    )
}

/// The base cache directory: `$XDG_CACHE_HOME` when set to an absolute path, else `$HOME/.cache`.
fn cache_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Some(dir);
        }
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
}

/// Download one artifact from one server into `dest`, writing to a sibling temp file first and
/// renaming so a concurrent reader never sees a partial file. Returns whether it was fetched; any
/// error (network, non-success status, filesystem) returns false.
fn download(server: &str, build_id: &str, artifact: Artifact, dest: &Path) -> bool {
    let url = format!("{server}/buildid/{build_id}/{}", artifact.as_str());
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_per_read(Some(READ_TIMEOUT))
        .build()
        .into();
    let Ok(mut resp) = agent.get(&url).call() else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Some(parent) = dest.parent() else {
        return false;
    };
    if std::fs::create_dir_all(parent).is_err() {
        return false;
    }
    let tmp = parent.join(format!(
        ".{}.{}.{}.part",
        artifact.as_str(),
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed),
    ));
    let wrote = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        let mut reader = resp.body_mut().as_reader();
        std::io::copy(&mut reader, &mut file)?;
        file.sync_all()?;
        std::fs::rename(&tmp, dest)
    })()
    .is_ok();
    if !wrote {
        let _ = std::fs::remove_file(&tmp);
    }
    wrote
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_path_rejects_non_hex_build_id() {
        // Path-traversal attempts and other non-hex ids must not yield a cache path.
        assert!(cache_path("../etc/passwd", Artifact::Debuginfo).is_none());
        assert!(cache_path("", Artifact::Executable).is_none());
        assert!(cache_path("abc/def", Artifact::Debuginfo).is_none());
    }

    #[test]
    fn cache_path_lays_out_hex_id() {
        // Independent of the cache root: the tail is always <id>/<artifact> under the crate dir.
        let p = cache_path("d16533ec", Artifact::Debuginfo).expect("hex id yields a path");
        assert!(
            p.ends_with("coretriage/debuginfod/d16533ec/debuginfo"),
            "{p:?}"
        );
    }

    #[test]
    fn parse_servers_splits_on_whitespace_and_trims_slashes() {
        assert_eq!(
            parse_servers("  https://a.example/  https://b.example "),
            vec!["https://a.example", "https://b.example"]
        );
        assert!(parse_servers("").is_empty());
    }
}
