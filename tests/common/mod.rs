//! Shared helpers for the integration test suite.

use std::path::PathBuf;

/// Returns a path inside the OS temp directory for a test output file.
///
/// Several tests write their encrypted/decrypted bytes to disk so the round
/// trip can be inspected by hand. Routing those writes through the temp
/// directory keeps them out of the repository working tree (they previously
/// landed in the crate root as `encrypted.docx` / `decrypted.docx`).
pub fn temp_output_path(file_name: &str) -> PathBuf {
    std::env::temp_dir().join(file_name)
}
