//! Corpus and fixture manifests — plan §4.14.
//!
//! A corpus is a gate input, so an unversioned corpus edit can turn a red build
//! green. Every corpus and fixture directory carries a `manifest.toml`, and the
//! hash below is recomputed on every `verify-docs` run.
//!
//! The content hash is defined so it is reproducible on any machine: for every
//! file under the directory except `manifest.toml` and `.gitkeep`, sorted by
//! relative path, feed the path bytes, a NUL, then the file bytes. Sorting is
//! what makes it independent of directory order; the NUL is what stops
//! `ab/c` and `a/bc` from hashing alike.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Directories that carry a manifest. `annex-g` and `annex-c` are views computed
/// from `redteam ∪ benign`, not directories, so they have none.
pub(crate) const ASSET_DIRS: &[&str] = &[
    "tests/corpus/redteam",
    "tests/corpus/benign",
    "tests/corpus/flows",
    "tests/corpus/mobile-apps",
    "tests/fixtures/reference-trace",
];

/// The fields plan §4.14 requires of every manifest.
const REQUIRED: &[&str] = &[
    "schema",
    "version",
    "entry_count",
    "sha256",
    "produced_by",
    "licence",
];

pub(crate) struct Manifest {
    pub(crate) version: String,
    pub(crate) entry_count: i64,
    pub(crate) declared_hash: String,
    pub(crate) missing_fields: Vec<String>,
}

/// Read a manifest, or say why it could not be read.
pub(crate) fn read(dir: &str) -> Result<Manifest, String> {
    let path = Path::new(dir).join("manifest.toml");
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc: toml::Value = raw
        .parse()
        .map_err(|e| format!("{}: does not parse: {e}", path.display()))?;

    let missing_fields = REQUIRED
        .iter()
        .filter(|k| doc.get(*k).is_none())
        .map(|k| (*k).to_owned())
        .collect();

    Ok(Manifest {
        version: doc
            .get("version")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        entry_count: doc
            .get("entry_count")
            .and_then(toml::Value::as_integer)
            .unwrap_or(-1),
        declared_hash: doc
            .get("sha256")
            .and_then(toml::Value::as_str)
            .unwrap_or("")
            .to_owned(),
        missing_fields,
    })
}

/// Hash a directory's content by the rule in this module's documentation.
pub(crate) fn content_hash(dir: &str) -> std::io::Result<String> {
    let root = Path::new(dir);
    let mut files = Vec::new();
    collect(root, root, &mut files)?;
    files.sort();

    let mut hasher = Sha256::new();
    for rel in &files {
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0u8]);
        hasher.update(std::fs::read(root.join(rel))?);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else if !matches!(
            path.file_name().and_then(std::ffi::OsStr::to_str),
            Some("manifest.toml" | ".gitkeep")
        ) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

/// One line per asset, and a failure for each manifest that lies about its content.
///
/// Returns the failures; an empty vector means every declared hash matches.
pub(crate) fn check() -> Vec<String> {
    let mut failures = Vec::new();
    for dir in ASSET_DIRS {
        match read(dir) {
            Err(e) => failures.push(e),
            Ok(m) => {
                if !m.missing_fields.is_empty() {
                    failures.push(format!("{dir}: manifest lacks {:?}", m.missing_fields));
                }
                match content_hash(dir) {
                    Err(e) => failures.push(format!("{dir}: cannot hash: {e}")),
                    Ok(actual) => {
                        let state = if actual == m.declared_hash {
                            "matches"
                        } else {
                            failures.push(format!(
                                "{dir}: manifest says {}, content hashes to {actual}",
                                m.declared_hash
                            ));
                            "DIFFERS"
                        };
                        println!(
                            "  ----  {dir}  v{} · {} entries · sha256 {}",
                            m.version, m.entry_count, state
                        );
                    }
                }
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::{check, content_hash, read, ASSET_DIRS};

    fn at_root() {
        std::env::set_current_dir(crate::workspace_root()).unwrap();
    }

    /// sha256 of the empty string. An empty corpus must hash to it, or "empty"
    /// and "unreadable" would produce different values for the same absence.
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn every_asset_directory_has_a_complete_manifest() {
        at_root();
        for dir in ASSET_DIRS {
            let m = read(dir).unwrap_or_else(|e| panic!("{e}"));
            assert!(
                m.missing_fields.is_empty(),
                "{dir} lacks {:?}",
                m.missing_fields
            );
        }
    }

    #[test]
    fn an_empty_corpus_hashes_the_empty_string() {
        at_root();
        assert_eq!(content_hash("tests/corpus/redteam").unwrap(), EMPTY);
    }

    #[test]
    fn the_hash_covers_content_and_notices_a_change() {
        at_root();
        // Its own directory, not a real corpus: another test hashes those, and
        // tests run in parallel. Planting a file in shared state while a
        // measurement is running is how a green suite stops meaning anything
        // (general rule 11).
        let dir = format!("target/tmp-hash-test-{}", std::process::id());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/rf-01.toml"), "id = \"RF-01\"\n").unwrap();

        let before = content_hash(&dir).unwrap();
        let planted = format!("{dir}/rf-planted.toml");
        std::fs::write(&planted, "id = \"RF-planted\"\n").unwrap();
        let after = content_hash(&dir).unwrap();
        std::fs::remove_file(&planted).unwrap();
        let restored = content_hash(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_ne!(
            before, after,
            "adding a scenario did not change the corpus hash"
        );
        assert_eq!(restored, before, "removing it did not restore the hash");
    }

    #[test]
    fn declared_hashes_match_the_content_on_disk() {
        at_root();
        assert!(
            check().is_empty(),
            "a manifest disagrees with its directory"
        );
    }
}
