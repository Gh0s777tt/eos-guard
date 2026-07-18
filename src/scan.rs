//! Filesystem walk, hashing and the security lint.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// A file as observed on disk during a scan.
#[derive(Clone, Debug)]
pub struct Entry {
    pub path: String,
    pub hash: String,
    pub size: i64,
    pub mode: u32,
    pub mtime: i64,
}

impl Entry {
    /// Security-relevant permission bits, most dangerous first. Empty when the
    /// file has none. Surfaced by the audit regardless of change status.
    pub fn security_flags(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.mode & 0o4000 != 0 {
            flags.push("setuid");
        }
        if self.mode & 0o2000 != 0 {
            flags.push("setgid");
        }
        if self.mode & 0o0002 != 0 {
            flags.push("zapisywalny dla wszystkich");
        }
        flags
    }

    pub fn has_security_flags(&self) -> bool {
        self.mode & 0o6002 != 0
    }
}

fn blake3_file(path: &Path) -> std::io::Result<String> {
    let bytes = fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Recursively collect regular files under `root` (symlinks are not followed),
/// hashing each. `budget` caps the number of files so a huge tree can't hang the
/// UI; the returned bool is true if the cap was hit (coverage was truncated).
pub fn walk(root: &Path, out: &mut Vec<Entry>, budget: &mut usize) -> bool {
    let mut truncated = false;
    let Ok(rd) = fs::read_dir(root) else {
        return false;
    };
    let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if *budget == 0 {
            return true;
        }
        // Don't follow symlinks: use symlink_metadata to classify.
        let Ok(lmeta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let ft = lmeta.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            truncated |= walk(&path, out, budget);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let hash = match blake3_file(&path) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let mode = meta.permissions().mode();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        out.push(Entry {
            path: path.to_string_lossy().into_owned(),
            hash,
            size: meta.len() as i64,
            mode,
            mtime,
        });
        *budget -= 1;
    }
    truncated
}

/// Scan every root, hashing all regular files (up to `budget` total).
pub fn scan_roots(roots: &[String], budget: usize) -> (Vec<Entry>, bool) {
    let mut out = Vec::new();
    let mut left = budget;
    let mut truncated = false;
    for root in roots {
        if left == 0 {
            truncated = true;
            break;
        }
        truncated |= walk(Path::new(root), &mut out, &mut left);
    }
    (out, truncated)
}
