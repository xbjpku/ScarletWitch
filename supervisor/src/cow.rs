// Copy-on-write file management.
//
// For openat writes: copies the original file to a session-local directory and
// injects the COW copy's fd into the child via SECCOMP_IOCTL_NOTIF_ADDFD.
//
// For other write syscalls (mkdir, rename, chmod, symlink, truncate):
// the supervisor performs the operation in the COW layer on behalf of the child
// and returns a synthetic success (0).

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

use crate::notif;

const COW_MAX_ENTRIES: usize = 4096;

#[derive(Clone)]
struct CowEntry {
    orig_path: String,
    cow_path: PathBuf,
}

pub struct CowTable {
    entries: Vec<CowEntry>,
    /// Paths that have been "deleted" in the COW layer (whiteout).
    deleted: HashSet<String>,
    cow_dir: PathBuf,
    manifest_path: PathBuf,
    deleted_path: PathBuf,
}

impl CowTable {
    /// Initialize: create directories, load existing manifest and deletions.
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
        };

        // Load existing manifest (for session restart)
        if table.manifest_path.exists() {
            if let Err(e) = table.load_manifest() {
                eprintln!("[cow] load manifest: {}", e);
            }
        }
        // Load existing deletions
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

    /// Check if a path has been "deleted" in the COW layer.
    pub fn is_deleted(&self, orig_path: &str) -> bool {
        self.deleted.contains(orig_path)
    }

    /// Look up whether orig_path has a COW entry.
    pub fn lookup(&self, orig_path: &str) -> Option<&Path> {
        self.entries
            .iter()
            .find(|e| e.orig_path == orig_path)
            .map(|e| e.cow_path.as_path())
    }

    /// Get the COW path for an original path (whether or not it exists yet).
    fn cow_path_for(&self, orig_path: &str) -> PathBuf {
        self.cow_dir.join(orig_path.trim_start_matches('/'))
    }

    // ================================================================
    // openat COW — materialize file + inject fd
    // ================================================================

    /// Perform COW: copy original file to cow_dir, add entry, write manifest.
    pub fn materialize(
        &mut self,
        orig_path: &str,
        open_flags: i32,
        mode: u32,
    ) -> io::Result<()> {
        // Already exists?
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

        // Create parent directories
        if let Some(parent) = cow_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Copy original or create empty
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

        // Remove from deleted set if it was previously deleted
        self.deleted.remove(orig_path);

        self.entries.push(CowEntry {
            orig_path: orig_path.to_string(),
            cow_path,
        });

        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }

        Ok(())
    }

    /// Materialize a file for modification (no O_CREAT, no open_flags dependency).
    /// Used by chmod, truncate etc. that need the file to exist in COW first.
    fn ensure_materialized(&mut self, orig_path: &str) -> io::Result<PathBuf> {
        if let Some(p) = self.lookup(orig_path) {
            return Ok(p.to_path_buf());
        }
        // Materialize with O_WRONLY (just need to copy)
        self.materialize(orig_path, libc::O_WRONLY, 0o644)?;
        self.lookup(orig_path)
            .map(|p| p.to_path_buf())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "materialize failed"))
    }

    /// Open the COW copy and inject fd into child via SECCOMP_ADDFD.
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
    // Write-family COW operations (supervisor performs on behalf)
    // ================================================================

    /// COW mkdir: create directory in COW layer.
    pub fn cow_mkdir(&mut self, orig_path: &str, mode: u32) -> io::Result<()> {
        let cow_path = self.cow_path_for(orig_path);
        fs::create_dir_all(&cow_path)?;
        // Set permissions
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cow_path, fs::Permissions::from_mode(mode))?;
        self.deleted.remove(orig_path);
        eprintln!("[cow] mkdir {} -> {}", orig_path, cow_path.display());
        // Directories don't go in the file manifest (they're structural)
        Ok(())
    }

    /// COW rename: materialize source if needed, then rename within COW layer.
    /// Both src and dst are outside the write whitelist.
    pub fn cow_rename(&mut self, src_path: &str, dst_path: &str) -> io::Result<()> {
        // Materialize source if not already in COW
        let src_cow = if let Some(p) = self.lookup(src_path) {
            p.to_path_buf()
        } else {
            // Source exists on real FS, copy it in
            let orig = Path::new(src_path);
            if !orig.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("rename source {} does not exist", src_path),
                ));
            }
            self.materialize(src_path, libc::O_RDONLY, 0o644)?;
            self.lookup(src_path)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "materialize failed"))?
                .to_path_buf()
        };

        let dst_cow = self.cow_path_for(dst_path);
        if let Some(parent) = dst_cow.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::rename(&src_cow, &dst_cow)?;

        // Update entries: remove src, add dst
        self.entries.retain(|e| e.orig_path != src_path);
        self.entries.push(CowEntry {
            orig_path: dst_path.to_string(),
            cow_path: dst_cow.clone(),
        });
        self.deleted.remove(dst_path);

        if let Err(e) = self.save_manifest() {
            eprintln!("[cow] save manifest: {}", e);
        }

        eprintln!("[cow] rename {} -> {}", src_path, dst_path);
        Ok(())
    }

    /// COW symlink: create symlink in COW layer.
    pub fn cow_symlink(&mut self, target: &str, linkpath: &str) -> io::Result<()> {
        let cow_link = self.cow_path_for(linkpath);
        if let Some(parent) = cow_link.parent() {
            fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(target, &cow_link)?;
        self.deleted.remove(linkpath);
        eprintln!("[cow] symlink {} -> {}", linkpath, target);
        Ok(())
    }

    /// COW chmod: materialize file, then change permissions on the COW copy.
    pub fn cow_chmod(&mut self, orig_path: &str, mode: u32) -> io::Result<()> {
        let cow_path = self.ensure_materialized(orig_path)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cow_path, fs::Permissions::from_mode(mode))?;
        eprintln!("[cow] chmod {} mode={:o}", orig_path, mode);
        Ok(())
    }

    /// COW truncate: materialize file, then truncate the COW copy.
    pub fn cow_truncate(&mut self, orig_path: &str, length: i64) -> io::Result<()> {
        let cow_path = self.ensure_materialized(orig_path)?;
        let file = fs::OpenOptions::new().write(true).open(&cow_path)?;
        file.set_len(length as u64)?;
        eprintln!("[cow] truncate {} len={}", orig_path, length);
        Ok(())
    }

    // ================================================================
    // Manifest I/O — tree-indent format
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
            writeln!(f, "{:indent$}{}", "", parts[parts.len() - 1], indent = indent)?;

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
            let trimmed = line.trim();

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

                self.entries.push(CowEntry {
                    orig_path: orig,
                    cow_path,
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
        if n == 0 {
            break;
        }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

fn path_to_cstr(path: &Path) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

// Extension trait to set file mode on OpenOptions
trait OpenOptionsModeExt {
    fn mode_ext(&mut self, mode: u32) -> &mut Self;
}

impl OpenOptionsModeExt for fs::OpenOptions {
    fn mode_ext(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, mode)
    }
}
