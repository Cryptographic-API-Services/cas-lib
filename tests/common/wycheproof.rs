//! Downloads Project Wycheproof test vectors on demand.
//!
//! The vector files are not committed. Every test run resolves upstream `main`
//! of `C2SP/wycheproof` to its current commit and tests against the files in
//! `testvectors_v1/` at that commit, so a new upstream case the library gets
//! wrong fails the build. Files are cached under
//! `target/tmp/wycheproof/<commit>/` and only downloaded again when upstream
//! moves. See `tests/data/wycheproof/README.md`.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

/// The upstream ref tested by default. Set the `WYCHEPROOF_REF` environment
/// variable to a commit SHA, tag or branch to test against something else, e.g.
/// the commit logged by an earlier run to reproduce it.
const DEFAULT_REF: &str = "main";

const REPO: &str = "C2SP/wycheproof";
const VECTOR_DIR: &str = "testvectors_v1";

/// Tests in one binary run on parallel threads; download one file at a time.
static DOWNLOAD_LOCK: Mutex<()> = Mutex::new(());

/// The commit the requested ref resolved to, looked up once per test binary.
static RESOLVED_REF: OnceLock<String> = OnceLock::new();

/// Writes a line straight to stderr. `eprintln!` output is captured by the test
/// harness and hidden for passing tests, but the commit under test should be
/// visible in every run's log.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

fn cache_root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wycheproof")
}

fn requested_ref() -> String {
    match std::env::var("WYCHEPROOF_REF") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => DEFAULT_REF.to_string(),
    }
}

fn is_commit_sha(git_ref: &str) -> bool {
    git_ref.len() == 40 && git_ref.bytes().all(|b| b.is_ascii_hexdigit())
}

fn file_safe(git_ref: &str) -> String {
    git_ref
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect()
}

/// Asks the remote which commit a branch or tag currently points at.
fn ls_remote(git_ref: &str) -> Option<String> {
    let output = Command::new("git")
        .args(["ls-remote", &format!("https://github.com/{REPO}"), git_ref])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sha = stdout.split_whitespace().next()?;
    is_commit_sha(sha).then(|| sha.to_string())
}

/// Resolves the requested ref to a commit SHA.
///
/// Branches and tags move, so they are resolved on every run. If that fails
/// (offline, or `git` not on `PATH`) the commit from the last successful run is
/// reused with a warning; with no earlier run the ref is fetched by name.
fn resolve_ref() -> String {
    let requested = requested_ref();
    if is_commit_sha(&requested) {
        return requested;
    }

    let marker = cache_root().join(format!("{}.resolved", file_safe(&requested)));
    if let Some(sha) = ls_remote(&requested) {
        log!("Wycheproof vectors: {REPO}@{sha} ({requested})");
        let _ = std::fs::create_dir_all(cache_root());
        let _ = std::fs::write(&marker, &sha);
        return sha;
    }

    match std::fs::read_to_string(&marker) {
        Ok(sha) if is_commit_sha(sha.trim()) => {
            let sha = sha.trim().to_string();
            log!("warning: could not resolve {REPO}@{requested} (offline, or git not on PATH); reusing cached Wycheproof vectors from {sha}");
            sha
        }
        _ => requested,
    }
}

fn parse(path: &Path) -> Result<Value, String> {
    let contents = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(&contents).map_err(|err| err.to_string())?;
    if !value["testGroups"].is_array() {
        return Err("not a Wycheproof vector file (no testGroups array)".to_string());
    }
    Ok(value)
}

fn download(url: &str, target: &Path) -> Value {
    // Download to a temporary name and rename, so an interrupted run never
    // leaves a truncated file in the cache.
    let partial = target.with_extension(format!("{}.partial", std::process::id()));
    let status = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location"])
        // HTTPS only, including after a redirect.
        .args(["--proto", "=https", "--proto-redir", "=https"])
        .args(["--retry", "3", "--max-time", "120", "--output"])
        .arg(&partial)
        .arg(url)
        .status()
        .unwrap_or_else(|err| {
            panic!("could not run `curl` to download {url}: {err}. Wycheproof vectors are downloaded on first use; install curl or pre-populate {}", target.display())
        });
    if !status.success() {
        let _ = std::fs::remove_file(&partial);
        panic!("downloading {url} failed ({status}). Wycheproof vectors are downloaded on first use and need network access.");
    }

    // Fail here rather than with a confusing error inside a test.
    let value = parse(&partial).unwrap_or_else(|err| {
        let _ = std::fs::remove_file(&partial);
        panic!("{url} did not return a usable vector file: {err}")
    });
    std::fs::rename(&partial, target)
        .unwrap_or_else(|err| panic!("could not write {}: {err}", target.display()));
    value
}

/// Loads a Wycheproof vector file (e.g. `"aes_wrap_test.json"`), downloading it
/// first if it is not cached for the current upstream commit.
pub fn load(file_name: &str) -> Value {
    let _guard = DOWNLOAD_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let git_ref = RESOLVED_REF.get_or_init(resolve_ref);
    // Only a commit SHA is safe to cache; a ref fetched by name can move.
    let cacheable = is_commit_sha(git_ref);
    let dir = cache_root().join(file_safe(git_ref));
    let target = dir.join(file_name);

    if cacheable && target.exists() {
        match parse(&target) {
            Ok(value) => return value,
            Err(err) => log!("re-downloading {}: {err}", target.display()),
        }
    }

    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|err| panic!("could not create {}: {err}", dir.display()));
    let url = format!("https://raw.githubusercontent.com/{REPO}/{git_ref}/{VECTOR_DIR}/{file_name}");
    log!("Fetching Wycheproof vectors: {file_name} from {REPO}@{git_ref}");
    download(&url, &target)
}
