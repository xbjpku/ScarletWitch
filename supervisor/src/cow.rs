// Copy-on-write file management.
//
// For openat writes: copies the original file to a session-local directory and
// injects the COW copy's fd into the child via SECCOMP_IOCTL_NOTIF_ADDFD.
//
// For other write syscalls (mkdir, rename, chmod, symlink, truncate):
// the supervisor performs the operation in the COW layer on behalf of the child
// and returns a synthetic success (0).
//
// Each entry tracks metadata: operation type, triggering command, timestamp.

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::notif;

const COW_MAX_ENTRIES: usize = 4096;

// ================================================================
// Data structures
// ================================================================

#[derive(Clone)]
pub struct CowEntry {
    pub orig_path: String,
    pub cow_path: PathBuf,
    pub operation: String,  // "openat", "mkdir(legacy)", "fchmodat", etc.
    pub command: String,    // from /proc/{pid}/cmdline
    pub cmd_id: String,     // from SCARLET_CMD_ID env var (unique per tool call)
    pub timestamp: u64,     // unix epoch seconds
    pub generation: u64,    // kept for backward compat / ordering
}

pub struct CowTable {
    entries: Vec<CowEntry>,
    deleted: HashSet<String>,
    cow_dir: PathBuf,
    manifest_path: PathBuf,
    deleted_path: PathBuf,
    generation: u64,
}

/// Read /proc/{pid}/cmdline, replace NUL bytes with spaces.
pub fn read_command_context(pid: u32) -> String {
    fs::read(format!("/proc/{}/cmdline", pid))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

/// Read SCARLET_CMD_ID from /proc/{pid}/environ.
pub fn read_cmd_id(pid: u32) -> String {
    fs::read(format!("/proc/{}/environ", pid))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter_map(|s| {
                    let s = String::from_utf8_lossy(s);
                    s.strip_prefix("SCARLET_CMD_ID=").map(|v| v.to_string())
                })
                .next()
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl CowTable {
    pub fn init(session_dir: &Path) -> io::Result<Self> {
        let cow_dir = session_dir.join("cow_files");
        let manifest_path = session_dir.join("cow_tree");
        let deleted_path = session_dir.join(".deleted");

        fs::create_dir_all(session_dir)?;
        fs::create_dir_all(&cow_dir)?;

        let mut table = CowTable {
            entries: Vec::new(),
            deleted: HashSet::new(),
            cow_dir,
            manifest_path,
            deleted_path,
            generation: 0,
        };

        if table.manifest_path.exists() {
            if let Err(e) = table.load_manifest() {
                eprintln!("[cow] load manifest: {}", e);
            }
        }
        if table.deleted_path.exists() {
            if let Err(e) = table.load_deleted() {
                eprintln!("[cow] load deleted: {}", e);
            }
        }

        eprintln!(
            "[cow] initialized: cow_dir={}, entries={}, deleted={}",
            table.cow_dir.display(),
            table.entries.len(),
            table.deleted.len()
        );
        Ok(table)
    }

    pub fn is_deleted(&self, orig_path: &str) -> bool {
        self.deleted.contains(orig_path)
    }

    /// Return the cow_path for the LATEST entry of `orig_path`.
    pub fn lookup(&self, orig_path: &str) -> Option<&Path> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.orig_path == orig_path)
            .map(|e| e.cow_path.as_path())
    }

    /// Called on COW-HIT when the file is opened for writing.
    /// If the current generation is newer than the latest entry's, snapshot
    /// the current cow file (rename to .v{N}) and create a fresh cow copy
    /// so the new command writes to its own version.
    pub fn snapshot_for_reopen(
        &mut self,
        orig_path: &str,
        operation: &str,
        command: &str,
        cmd_id: &str,
    ) -> io::Result<()> {
        // Find the latest entry for this file
        let latest_idx = self.entries.iter().rposition(|e| e.orig_path == orig_path);
        let latest_idx = match latest_idx {
            Some(i) => i,
            None => return Ok(()),
        };

        // Only snapshot if this is a different command (different cmd_id)
        if self.entries[latest_idx].cmd_id == cmd_id {
            return Ok(());
        }

        // Count how many entries already exist for this file (= version number)
        let version = self.entries.iter().filter(|e| e.orig_path == orig_path).count();

        let cur_cow_path = self.entries[latest_idx].cow_path.clone();
        if !cur_cow_path.exists() {
            return Ok(());
        }

        // Rename current cow file to a versioned path
        let versioned = cur_cow_path.with_extension(format!("v{}", version - 1));
        fs::rename(&cur_cow_path, &versioned)?;

        // Copy the versioned file back so the new command starts from the same content
        copy_file(&versioned, &cur_cow_path)?;

        // Update old entry to point at the versioned path
        self.entries[latest_idx].cow_path = versioned;

        self.resolve_generation(cmd_id);
        self.entries.push(CowEntry {
            orig_path: orig_path.to_string(),
            cow_path: cur_cow_path,
            operation: operation.to_string(),
            command: command.to_string(),
            timestamp: now_epoch(),
            cmd_id: cmd_id.to_string(),
            generation: self.generation,
        });

        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }
        eprintln!(
            "[cow] snapshot: {} v{} -> new entry (gen={})",
            orig_path, version - 1, self.generation
        );
        Ok(())
    }

    pub fn entries(&self) -> &[CowEntry] {
        &self.entries
    }

    /// Resolve the generation for a cmd_id.
    /// Same cmd_id always gets the same generation (handles parallel interleaving).
    /// New cmd_id gets a new (incremented) generation.
    fn resolve_generation(&mut self, cmd_id: &str) {
        if cmd_id.is_empty() { return; }
        // Reuse generation if we've seen this cmd_id before
        for e in self.entries.iter().rev() {
            if e.cmd_id == cmd_id {
                self.generation = e.generation;
                return;
            }
        }
        // New cmd_id — increment
        self.generation += 1;
    }

    pub fn deleted_paths(&self) -> &HashSet<String> {
        &self.deleted
    }

    fn cow_path_for(&self, orig_path: &str) -> PathBuf {
        self.cow_dir.join(orig_path.trim_start_matches('/'))
    }

    // ================================================================
    // openat COW — materialize file + inject fd
    // ================================================================

    pub fn materialize(
        &mut self,
        orig_path: &str,
        open_flags: i32,
        mode: u32,
        operation: &str,
        command: &str,
        cmd_id: &str,
    ) -> io::Result<()> {
        if self.lookup(orig_path).is_some() {
            return Ok(());
        }

        if self.entries.len() >= COW_MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("COW table full ({} entries)", COW_MAX_ENTRIES),
            ));
        }

        let cow_path = self.cow_path_for(orig_path);
        if let Some(parent) = cow_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let orig = Path::new(orig_path);
        if orig.exists() {
            let meta = fs::metadata(orig)?;
            if !meta.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("not a regular file: {}", orig_path),
                ));
            }
            copy_file(orig, &cow_path)?;
            eprintln!("[cow] copied {} -> {}", orig_path, cow_path.display());
        } else if open_flags & libc::O_CREAT != 0 {
            let f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode_ext(mode)
                .open(&cow_path)?;
            drop(f);
            eprintln!("[cow] created empty {}", cow_path.display());
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("original {} does not exist and no O_CREAT", orig_path),
            ));
        }

        self.deleted.remove(orig_path);
        self.resolve_generation(cmd_id);
        self.entries.push(CowEntry {
            orig_path: orig_path.to_string(),
            cow_path,
            operation: operation.to_string(),
            command: command.to_string(),
            timestamp: now_epoch(),
            cmd_id: cmd_id.to_string(),
            generation: self.generation,
        });

        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }
        Ok(())
    }

    fn ensure_materialized(&mut self, orig_path: &str, operation: &str, command: &str, cmd_id: &str) -> io::Result<PathBuf> {
        if self.lookup(orig_path).is_some() {
            // Already in cow — create versioned snapshot if generation advanced
            self.snapshot_for_reopen(orig_path, operation, command, cmd_id)?;
            return Ok(self.lookup(orig_path).unwrap().to_path_buf());
        }
        self.materialize(orig_path, libc::O_WRONLY, 0o644, operation, command, cmd_id)?;
        self.lookup(orig_path)
            .map(|p| p.to_path_buf())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "materialize failed"))
    }

    pub fn inject_fd(
        &self,
        notify_fd: RawFd,
        req_id: u64,
        cow_path: &Path,
        open_flags: i32,
        mode: i32,
    ) -> io::Result<i32> {
        let sv_flags = open_flags & (libc::O_ACCMODE | libc::O_APPEND | libc::O_TRUNC);
        let sv_fd = unsafe { libc::open(path_to_cstr(cow_path)?.as_ptr(), sv_flags, mode) };
        if sv_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        if let Err(e) = notif::id_valid(notify_fd, req_id) {
            unsafe { libc::close(sv_fd) };
            return Err(e);
        }
        let result = notif::inject_fd_send(notify_fd, req_id, sv_fd, open_flags, mode);
        unsafe { libc::close(sv_fd) };
        result
    }

    // ================================================================
    // Write-family COW operations
    // ================================================================

    pub fn cow_mkdir(&mut self, orig_path: &str, mode: u32, operation: &str, command: &str, cmd_id: &str) -> io::Result<()> {
        let cow_path = self.cow_path_for(orig_path);
        fs::create_dir_all(&cow_path)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cow_path, fs::Permissions::from_mode(mode))?;
        self.deleted.remove(orig_path);
        // Track mkdir as an entry too (so it shows up in LIST_COW)
        self.entries.push(CowEntry {
            orig_path: orig_path.to_string(),
            cow_path,
            operation: operation.to_string(),
            command: command.to_string(),
            timestamp: now_epoch(),
            cmd_id: cmd_id.to_string(),
            generation: self.generation,
        });
        if let Err(e) = self.save_manifest() { eprintln!("[cow] save manifest: {}", e); }
        eprintln!("[cow] mkdir {} -> {}", orig_path, self.cow_path_for(orig_path).display());
        Ok(())
    }

    pub fn cow_rename(&mut self, src_path: &str, dst_path: &str, operation: &str, command: &str, cmd_id: &str) -> io::Result<()> {
        let src_cow = if let Some(p) = self.lookup(src_path) {
            p.to_path_buf()
        } else {
            let orig = Path::new(src_path);
            if !orig.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("rename source {} does not exist", src_path),
                ));
            }
            self.materialize(src_path, libc::O_RDONLY, 0o644, operation, command, cmd_id)?;
            self.lookup(src_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "materialize failed"))?
                .to_path_buf()
        };

        let dst_cow = self.cow_path_for(dst_path);
        if let Some(parent) = dst_cow.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src_cow, &dst_cow)?;

        self.entries.retain(|e| e.orig_path != src_path);
        self.entries.push(CowEntry {
            orig_path: dst_path.to_string(),
            cow_path: dst_cow,
            operation: operation.to_string(),
            command: command.to_string(),
            timestamp: now_epoch(),
            cmd_id: cmd_id.to_string(),
            generation: self.generation,
        });
        self.deleted.remove(dst_path);

        if let Err(e) = self.save_manifest() { eprintln!("[cow] save manifest: {}", e); }
        eprintln!("[cow] rename {} -> {}", src_path, dst_path);
        Ok(())
    }

    pub fn cow_symlink(&mut self, target: &str, linkpath: &str, operation: &str, command: &str, cmd_id: &str) -> io::Result<()> {
        let cow_link = self.cow_path_for(linkpath);
        if let Some(parent) = cow_link.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &cow_link)?;
        self.deleted.remove(linkpath);
        self.entries.push(CowEntry {
            orig_path: linkpath.to_string(),
            cow_path: cow_link,
            operation: operation.to_string(),
            command: command.to_string(),
            timestamp: now_epoch(),
            cmd_id: cmd_id.to_string(),
            generation: self.generation,
        });
        if let Err(e) = self.save_manifest() { eprintln!("[cow] save manifest: {}", e); }
        eprintln!("[cow] symlink {} -> {}", linkpath, target);
        Ok(())
    }

    pub fn cow_chmod(&mut self, orig_path: &str, mode: u32, operation: &str, command: &str, cmd_id: &str) -> io::Result<()> {
        let cow_path = self.ensure_materialized(orig_path, operation, command, cmd_id)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cow_path, fs::Permissions::from_mode(mode))?;
        eprintln!("[cow] chmod {} mode={:o}", orig_path, mode);
        Ok(())
    }

    pub fn cow_truncate(&mut self, orig_path: &str, length: i64, operation: &str, command: &str, cmd_id: &str) -> io::Result<()> {
        let cow_path = self.ensure_materialized(orig_path, operation, command, cmd_id)?;
        let file = fs::OpenOptions::new().write(true).open(&cow_path)?;
        file.set_len(length as u64)?;
        eprintln!("[cow] truncate {} len={}", orig_path, length);
        Ok(())
    }

    // ================================================================
    // unlink / rmdir — only for files created in the cow layer
    // ================================================================

    /// Returns true if orig_path was created in the cow layer (not on the real FS).
    pub fn is_cow_created(&self, orig_path: &str) -> bool {
        // A cow-created file has a cow entry but does NOT exist on the real filesystem
        self.lookup(orig_path).is_some() && !Path::new(orig_path).exists()
    }

    pub fn cow_unlink(&mut self, orig_path: &str, _operation: &str, _command: &str, _cmd_id: &str) -> io::Result<()> {
        // Remove the cow file
        if let Some(cp) = self.lookup(orig_path) {
            let cp = cp.to_path_buf();
            if cp.exists() { let _ = fs::remove_file(&cp); }
        }
        // Remove ALL entries for this path (including versioned ones) and their cow files
        for e in self.entries.iter().filter(|e| e.orig_path == orig_path) {
            if e.cow_path.exists() { let _ = fs::remove_file(&e.cow_path); }
        }
        self.entries.retain(|e| e.orig_path != orig_path);
        if let Err(e) = self.save_manifest() { eprintln!("[cow] save manifest: {}", e); }
        eprintln!("[cow] unlink (cow-created) {}", orig_path);
        Ok(())
    }

    pub fn cow_rmdir(&mut self, orig_path: &str, _operation: &str, _command: &str, _cmd_id: &str) -> io::Result<()> {
        let cow_path = self.cow_path_for(orig_path);
        if cow_path.exists() && cow_path.is_dir() {
            let _ = fs::remove_dir_all(&cow_path);
        }
        self.entries.retain(|e| e.orig_path != orig_path);
        if let Err(e) = self.save_manifest() { eprintln!("[cow] save manifest: {}", e); }
        eprintln!("[cow] rmdir (cow-created) {}", orig_path);
        Ok(())
    }

    // ================================================================
    // DAG simplification — three review levels
    // ================================================================

    /// strict: show every version, only drop entries whose diff vs previous
    ///         version is exactly zero (content + permissions identical).
    /// medium: strict + eliminate entire chains where final == original on disk.
    /// loose:  medium + fold intermediate versions, keeping only the last entry
    ///         per file (diff shown as original→final).
    pub fn simplify(&self, level: &str) -> Vec<CowEntry> {
        let by_path = self.group_by_path();

        let mut result: Vec<CowEntry> = Vec::new();
        for (orig_path, chain) in &by_path {
            if chain.is_empty() { continue; }

            // Step 1 (all levels): drop entries identical to their predecessor
            let mut deduped: Vec<&CowEntry> = vec![chain[0]];
            for i in 1..chain.len() {
                if !Self::cow_files_equal(&deduped.last().unwrap().cow_path, &chain[i].cow_path) {
                    deduped.push(chain[i]);
                }
            }

            // Step 2 (medium, loose): drop entire chain if net-zero vs original
            if level != "strict" {
                if let Some(last) = deduped.last() {
                    if Self::matches_original(orig_path, &last.cow_path) {
                        continue;
                    }
                }
            }

            // Step 3 (loose): fold to only the last entry per file
            if level == "loose" {
                if let Some(last) = deduped.last() {
                    result.push((*last).clone());
                }
                continue;
            }

            result.extend(deduped.iter().map(|e| (*e).clone()));
        }

        result.sort_by_key(|e| e.generation);
        result
    }

    fn group_by_path(&self) -> std::collections::HashMap<&str, Vec<&CowEntry>> {
        let mut by_path: std::collections::HashMap<&str, Vec<&CowEntry>> = std::collections::HashMap::new();
        for e in &self.entries {
            by_path.entry(&e.orig_path).or_default().push(e);
        }
        by_path
    }

    fn cow_files_equal(a: &Path, b: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let a_content = fs::read(a).unwrap_or_default();
        let b_content = fs::read(b).unwrap_or_default();
        if a_content != b_content { return false; }
        let a_mode = fs::metadata(a).map(|m| m.permissions().mode()).unwrap_or(0);
        let b_mode = fs::metadata(b).map(|m| m.permissions().mode()).unwrap_or(0);
        a_mode == b_mode
    }

    fn matches_original(orig_path: &str, cow_path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        let orig = Path::new(orig_path);
        if !orig.exists() || !cow_path.exists() { return false; }
        let orig_content = fs::read(orig).unwrap_or_default();
        let cow_content = fs::read(cow_path).unwrap_or_default();
        if orig_content != cow_content { return false; }
        let orig_mode = fs::metadata(orig).map(|m| m.permissions().mode()).unwrap_or(0);
        let cow_mode = fs::metadata(cow_path).map(|m| m.permissions().mode()).unwrap_or(0);
        orig_mode == cow_mode
    }

    // ================================================================
    // Commit / Discard
    // ================================================================

    /// Commit selected COW entries: copy the LATEST cow→orig, remove ALL cow
    /// versions for committed files, remove from table.
    pub fn commit_paths(&mut self, paths: &[String]) -> io::Result<Vec<String>> {
        let mut committed = Vec::new();
        for path in paths {
            // lookup returns the latest entry
            if let Some(cow_path) = self.lookup(path) {
                let cow_path = cow_path.to_path_buf();
                // Create parent dir on real FS if needed
                if let Some(parent) = Path::new(path.as_str()).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if cow_path.is_symlink() {
                    let target = fs::read_link(&cow_path)?;
                    let dest = Path::new(path.as_str());
                    let _ = fs::remove_file(dest);
                    std::os::unix::fs::symlink(&target, dest)?;
                } else if cow_path.is_dir() {
                    fs::create_dir_all(path)?;
                    // Copy contents of COW dir to real dir
                    if let Ok(entries) = fs::read_dir(&cow_path) {
                        for entry in entries.flatten() {
                            let dest = Path::new(path.as_str()).join(entry.file_name());
                            if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                                let _ = fs::copy(entry.path(), &dest);
                            }
                        }
                    }
                } else {
                    fs::copy(&cow_path, path)?;
                }
                // Clean up the COW file/dir
                if cow_path.is_dir() {
                    let _ = fs::remove_dir_all(&cow_path);
                } else {
                    let _ = fs::remove_file(&cow_path);
                }
                committed.push(path.clone());
                eprintln!("[cow] committed {} <- {}", path, cow_path.display());
            }
        }
        // Remove ALL entries (including versioned snapshots) for committed files.
        // Also clean up versioned cow files.
        for path in &committed {
            for entry in self.entries.iter().filter(|e| &e.orig_path == path) {
                if entry.cow_path.exists() {
                    if entry.cow_path.is_dir() {
                        let _ = fs::remove_dir_all(&entry.cow_path);
                    } else {
                        let _ = fs::remove_file(&entry.cow_path);
                    }
                }
            }
        }
        self.entries.retain(|e| !committed.contains(&e.orig_path));
        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }
        // If all entries committed, do a full reset
        if self.entries.is_empty() {
            self.reset_cow_dir();
        }
        Ok(committed)
    }

    /// Commit all changes with generation ≤ max_gen.
    /// For each unique file, copy the highest-gen (≤ max_gen) cow version to
    /// the real path.  Remove those entries + their cow files.  Keep entries
    /// with generation > max_gen untouched.
    pub fn commit_up_to_gen(&mut self, max_gen: u64) -> io::Result<Vec<String>> {
        // Collect unique orig_paths that have entries at gen ≤ max_gen.
        // For each, find the entry with the highest gen ≤ max_gen.
        let mut best: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, e) in self.entries.iter().enumerate() {
            if e.generation <= max_gen {
                let prev = best.get(&e.orig_path).copied();
                if prev.is_none() || self.entries[prev.unwrap()].generation < e.generation {
                    best.insert(e.orig_path.clone(), i);
                }
            }
        }

        let mut committed = Vec::new();
        for (orig, idx) in &best {
            let cow_path = &self.entries[*idx].cow_path;
            if !cow_path.exists() { continue; }
            if let Some(parent) = Path::new(orig.as_str()).parent() {
                let _ = fs::create_dir_all(parent);
            }
            if cow_path.is_symlink() {
                let target = fs::read_link(cow_path)?;
                let dest = Path::new(orig.as_str());
                let _ = fs::remove_file(dest); // remove existing if any
                std::os::unix::fs::symlink(&target, dest)?;
            } else if cow_path.is_dir() {
                fs::create_dir_all(orig)?;
                if let Ok(rd) = fs::read_dir(cow_path) {
                    for de in rd.flatten() {
                        let dest = Path::new(orig.as_str()).join(de.file_name());
                        if de.file_type().map(|t| t.is_file()).unwrap_or(false) {
                            let _ = fs::copy(de.path(), &dest);
                        }
                    }
                }
            } else {
                fs::copy(cow_path, orig)?;
            }
            committed.push(orig.clone());
            eprintln!("[cow] committed (gen≤{}) {} <- {}", max_gen, orig, cow_path.display());
        }

        // Remove cow files for all entries with gen ≤ max_gen
        for e in self.entries.iter().filter(|e| e.generation <= max_gen) {
            if e.cow_path.exists() {
                if e.cow_path.is_dir() {
                    let _ = fs::remove_dir_all(&e.cow_path);
                } else {
                    let _ = fs::remove_file(&e.cow_path);
                }
            }
        }
        self.entries.retain(|e| e.generation > max_gen);

        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }
        if self.entries.is_empty() {
            self.reset_cow_dir();
        }
        Ok(committed)
    }

    /// Reset COW state: clear entries, delete cow_files contents, rewrite manifest.
    /// Called after all entries are committed or after DISCARD.
    fn reset_cow_dir(&mut self) {
        if self.cow_dir.exists() {
            for entry in fs::read_dir(&self.cow_dir).into_iter().flatten().flatten() {
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    let _ = fs::remove_dir_all(entry.path());
                } else {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        self.entries.clear();
        self.deleted.clear();
        let _ = self.save_manifest();
        eprintln!("[cow] reset: cow_dir cleaned, manifest cleared");
    }

    /// Discard all COW state.
    pub fn discard_all(&mut self) -> io::Result<()> {
        self.reset_cow_dir();
        eprintln!("[cow] discarded all entries");
        Ok(())
    }

    // ================================================================
    // JSON serialization (for LIST_COW)
    // ================================================================

    pub fn to_json(&self, level: &str) -> String {
        let simplified = self.simplify(level);
        let entries_json: Vec<String> = simplified
            .iter()
            .map(|e| {
                format!(
                    r#"{{"orig_path":"{}","cow_path":"{}","operation":"{}","command":"{}","cmd_id":"{}","timestamp":{},"generation":{}}}"#,
                    json_escape(&e.orig_path),
                    json_escape(&e.cow_path.to_string_lossy()),
                    json_escape(&e.operation),
                    json_escape(&e.command),
                    json_escape(&e.cmd_id),
                    e.timestamp,
                    e.generation
                )
            })
            .collect();

        let deleted_json: Vec<String> = self
            .deleted
            .iter()
            .map(|p| format!(r#""{}""#, json_escape(p)))
            .collect();

        format!(
            r#"{{"entries":[{}],"deleted":[{}],"count":{}}}"#,
            entries_json.join(","),
            deleted_json.join(","),
            simplified.len()
        )
    }

    // ================================================================
    // Manifest I/O
    // ================================================================

    fn save_manifest(&self) -> io::Result<()> {
        let mut sorted: Vec<&CowEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.orig_path.cmp(&b.orig_path));

        let mut f = fs::File::create(&self.manifest_path)?;
        writeln!(f, "/")?;

        let mut prev_parts: Vec<String> = Vec::new();

        for entry in &sorted {
            let path = &entry.orig_path;
            if !path.starts_with('/') {
                continue;
            }

            let parts: Vec<&str> = path
                .trim_start_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                continue;
            }

            let common = prev_parts
                .iter()
                .zip(parts.iter())
                .take(parts.len().saturating_sub(1))
                .take_while(|(a, b)| a.as_str() == **b)
                .count();

            for d in common..parts.len().saturating_sub(1) {
                let indent = (d + 1) * 2;
                writeln!(f, "{:indent$}{}/", "", parts[d], indent = indent)?;
            }

            let depth = parts.len();
            let indent = depth * 2;
            // Append metadata as comment: # op=openat cmd=echo... ts=1713168000
            writeln!(
                f,
                "{:indent$}{}  # op={} ts={}",
                "",
                parts[parts.len() - 1],
                entry.operation,
                entry.timestamp,
                indent = indent
            )?;

            prev_parts = parts.iter().map(|s| s.to_string()).collect();
        }

        Ok(())
    }

    fn load_manifest(&mut self) -> io::Result<()> {
        let file = fs::File::open(&self.manifest_path)?;
        let reader = BufReader::new(file);
        let mut dir_stack: Vec<String> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.trim() == "/" {
                dir_stack.clear();
                continue;
            }

            let indent = line.len() - line.trim_start().len();
            let level = indent / 2;

            // Strip inline comment: "filename  # op=openat ts=123"
            let trimmed_full = line.trim();
            let (trimmed, meta_comment) = if let Some(idx) = trimmed_full.find("  # ") {
                (&trimmed_full[..idx], Some(&trimmed_full[idx + 4..]))
            } else {
                (trimmed_full, None)
            };

            if trimmed.is_empty() {
                continue;
            }

            dir_stack.truncate(level);

            if trimmed.ends_with('/') {
                let dir_name = &trimmed[..trimmed.len() - 1];
                dir_stack.push(dir_name.to_string());
            } else {
                if self.entries.len() >= COW_MAX_ENTRIES {
                    break;
                }

                let mut orig = String::from("/");
                for dir in &dir_stack {
                    orig.push_str(dir);
                    orig.push('/');
                }
                orig.push_str(trimmed);

                let cow_path = self.cow_dir.join(orig.trim_start_matches('/'));

                // Parse metadata from comment
                let (operation, timestamp) = parse_meta_comment(meta_comment);

                self.entries.push(CowEntry {
                    orig_path: orig,
                    cow_path,
                    operation,
                    command: String::new(),
                    cmd_id: String::new(),
                    timestamp,
                    generation: 0,
                });
            }
        }

        eprintln!("[cow] loaded {} entries from manifest", self.entries.len());
        Ok(())
    }

    fn load_deleted(&mut self) -> io::Result<()> {
        let file = fs::File::open(&self.deleted_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim().to_string();
            if !line.is_empty() && !line.starts_with('#') {
                self.deleted.insert(line);
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn save_deleted(&self) -> io::Result<()> {
        let mut f = fs::File::create(&self.deleted_path)?;
        let mut sorted: Vec<&String> = self.deleted.iter().collect();
        sorted.sort();
        for path in sorted {
            writeln!(f, "{}", path)?;
        }
        Ok(())
    }
}

// ================================================================
// Helpers
// ================================================================

fn copy_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut input = fs::File::open(src)?;
    let mut output = fs::File::create(dst)?;
    let mut buf = [0u8; 65536];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { break; }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

fn path_to_cstr(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn parse_meta_comment(comment: Option<&str>) -> (String, u64) {
    let mut operation = String::new();
    let mut timestamp = 0u64;
    if let Some(c) = comment {
        for part in c.split_whitespace() {
            if let Some(val) = part.strip_prefix("op=") {
                operation = val.to_string();
            } else if let Some(val) = part.strip_prefix("ts=") {
                timestamp = val.parse().unwrap_or(0);
            }
        }
    }
    (operation, timestamp)
}

trait OpenOptionsModeExt {
    fn mode_ext(&mut self, mode: u32) -> &mut Self;
}

impl OpenOptionsModeExt for fs::OpenOptions {
    fn mode_ext(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, mode)
    }
}
