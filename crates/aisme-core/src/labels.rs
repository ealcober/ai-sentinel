// SPDX-License-Identifier: Apache-2.0
//! `File.taint` labelling (`F1.ON.05`): the tree roots a network fetch labels.
//!
//! §2.14, `H-13` as corrected: a write by a tainted process labels the file, a
//! read of a labelled file taints the reader — that pair is the algebra in
//! [`crate::taint`] — and **a network fetch labels the target tree root**, so
//! every file under it is untrusted input before anything writes it. This
//! module is the root registry: which canonical path prefixes carry a label,
//! and what label a path therefore has. It is what makes `RF-09` reachable:
//! `git clone` runs as a *child* of the agent, the child exits, and the label
//! must survive on the tree for the agent's later read to acquire it.
//!
//! Bounded: a fixed number of roots, each a bounded path. A full registry
//! refuses and counts — a label silently dropped would be an absence read as
//! "clean", the wrong direction for a security product.

use crate::taint::Taint;

/// The longest root path the registry keeps, in bytes.
pub const MAX_ROOT_LEN: usize = 200;

/// A root the registry could not take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelError {
    /// Every slot is in use.
    Full,
    /// The path exceeds [`MAX_ROOT_LEN`].
    TooLong,
    /// An empty path labels nothing.
    Empty,
}

#[derive(Clone, Copy)]
struct Root {
    path: [u8; MAX_ROOT_LEN],
    len: u16,
    taint: Taint,
}

/// The labelled tree roots of one session.
pub struct TreeLabels {
    roots: Vec<Root>,
    refused: u64,
}

impl TreeLabels {
    /// A registry for at most `capacity` roots, allocated once.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> TreeLabels {
        TreeLabels {
            roots: Vec::with_capacity(capacity),
            refused: 0,
        }
    }

    /// Label a tree root. A root labelled twice accumulates; a path under an
    /// existing root gets its own entry, so a narrower label is never lost
    /// under a wider one.
    ///
    /// # Errors
    ///
    /// [`LabelError`]; the refusal is counted and nothing changes.
    pub fn label_root(&mut self, path: &[u8], taint: Taint) -> Result<(), LabelError> {
        let path = strip_trailing_separators(path);
        if path.is_empty() {
            return Err(LabelError::Empty);
        }
        if path.len() > MAX_ROOT_LEN {
            self.refused += 1;
            return Err(LabelError::TooLong);
        }
        if let Some(root) = self.roots.iter_mut().find(|r| r.bytes() == path) {
            root.taint = root.taint.union(taint);
            return Ok(());
        }
        if self.roots.len() == self.roots.capacity() {
            self.refused += 1;
            return Err(LabelError::Full);
        }
        let mut stored = [0u8; MAX_ROOT_LEN];
        stored[..path.len()].copy_from_slice(path);
        #[allow(clippy::cast_possible_truncation)] // path.len() <= MAX_ROOT_LEN
        self.roots.push(Root {
            path: stored,
            len: path.len() as u16,
            taint,
        });
        Ok(())
    }

    /// The label a path carries from the roots above it: the union over every
    /// root the path is the root itself or lies under. A prefix match is on
    /// path components, so `/work/repo` labels `/work/repo/x` and not
    /// `/work/repo2`.
    #[must_use]
    pub fn label_for(&self, path: &[u8]) -> Taint {
        let path = strip_trailing_separators(path);
        self.roots
            .iter()
            .filter(|root| is_under(path, root.bytes()))
            .fold(Taint::EMPTY, |acc, root| acc.union(root.taint))
    }

    /// The effective taint of a file: its own label (what tainted writers
    /// left, `Taint::label_on_write`) plus what its tree carries.
    #[must_use]
    pub fn effective(&self, own: Taint, path: &[u8]) -> Taint {
        own.union(self.label_for(path))
    }

    /// Roots held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether no root is labelled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Labels refused because the registry was full or the path too long.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }
}

impl Root {
    fn bytes(&self) -> &[u8] {
        &self.path[..usize::from(self.len)]
    }
}

impl core::fmt::Debug for TreeLabels {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TreeLabels")
            .field("roots", &self.roots.len())
            .field("refused", &self.refused)
            .finish()
    }
}

fn strip_trailing_separators(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    &path[..end]
}

/// Whether `path` is `root` or a descendant of it, by components.
fn is_under(path: &[u8], root: &[u8]) -> bool {
    if root == b"/" {
        return path.starts_with(b"/");
    }
    path.starts_with(root) && (path.len() == root.len() || path[root.len()] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_covers_the_tree_by_components_not_by_prefix_bytes() {
        let mut labels = TreeLabels::with_capacity(4);
        labels
            .label_root(b"/work/repo/", Taint::UNTRUSTED_INPUT)
            .unwrap();
        assert_eq!(labels.label_for(b"/work/repo"), Taint::UNTRUSTED_INPUT);
        assert_eq!(
            labels.label_for(b"/work/repo/README.md"),
            Taint::UNTRUSTED_INPUT
        );
        assert_eq!(
            labels.label_for(b"/work/repo/a/b/c"),
            Taint::UNTRUSTED_INPUT
        );
        assert_eq!(
            labels.label_for(b"/work/repo2/x"),
            Taint::EMPTY,
            "not a component match"
        );
        assert_eq!(
            labels.label_for(b"/work"),
            Taint::EMPTY,
            "the parent is not labelled"
        );
        assert_eq!(labels.label_for(b"/other"), Taint::EMPTY);
    }

    #[test]
    fn nested_roots_accumulate_and_relabelling_unions() {
        let mut labels = TreeLabels::with_capacity(4);
        labels.label_root(b"/work", Taint::UNTRUSTED_INPUT).unwrap();
        labels
            .label_root(b"/work/secrets", Taint::SECRET_MATERIAL)
            .unwrap();
        labels.label_root(b"/work", Taint::GENERATED_CODE).unwrap();
        assert_eq!(labels.len(), 2);
        assert_eq!(
            labels.label_for(b"/work/x"),
            Taint::UNTRUSTED_INPUT | Taint::GENERATED_CODE
        );
        assert_eq!(
            labels.label_for(b"/work/secrets/key"),
            Taint::UNTRUSTED_INPUT | Taint::GENERATED_CODE | Taint::SECRET_MATERIAL
        );
        assert_eq!(
            labels.effective(Taint::CREDENTIAL_ACCESS, b"/work/y"),
            Taint::CREDENTIAL_ACCESS | Taint::UNTRUSTED_INPUT | Taint::GENERATED_CODE
        );
        assert_eq!(
            labels.effective(Taint::CREDENTIAL_ACCESS, b"/elsewhere"),
            Taint::CREDENTIAL_ACCESS
        );
    }

    #[test]
    fn a_full_registry_refuses_and_counts_rather_than_dropping_a_label() {
        let mut labels = TreeLabels::with_capacity(1);
        labels.label_root(b"/a", Taint::UNTRUSTED_INPUT).unwrap();
        assert_eq!(
            labels.label_root(b"/b", Taint::UNTRUSTED_INPUT),
            Err(LabelError::Full)
        );
        assert_eq!(
            labels.label_root(&[b'x'; MAX_ROOT_LEN + 1], Taint::UNTRUSTED_INPUT),
            Err(LabelError::TooLong)
        );
        assert_eq!(
            labels.label_root(b"", Taint::UNTRUSTED_INPUT),
            Err(LabelError::Empty)
        );
        assert_eq!(
            labels.label_root(b"///", Taint::UNTRUSTED_INPUT),
            Err(LabelError::Full),
            "root '/' is a path"
        );
        assert_eq!(labels.refused(), 3);
        assert_eq!(labels.len(), 1);
        // Relabelling the existing root still works when full.
        labels.label_root(b"/a", Taint::SECRET_MATERIAL).unwrap();
        assert_eq!(
            labels.label_for(b"/a/x"),
            Taint::UNTRUSTED_INPUT | Taint::SECRET_MATERIAL
        );
    }

    #[test]
    fn the_filesystem_root_covers_everything() {
        let mut labels = TreeLabels::with_capacity(1);
        labels.label_root(b"/", Taint::UNTRUSTED_INPUT).unwrap();
        assert_eq!(
            labels.label_for(b"/anything/at/all"),
            Taint::UNTRUSTED_INPUT
        );
        assert_eq!(
            labels.label_for(b"relative"),
            Taint::EMPTY,
            "not canonical, not under /"
        );
    }
}
