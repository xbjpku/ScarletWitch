// Whitelist rule engine — port from whitelist.c
//
// Double-buffered rulesets with atomic index swap for lock-free hot reload.
// Config format:
//   [write]     — whitelist: only listed prefixes are writable
//   [read]      — blacklist: listed prefixes are NOT readable

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_RULES: usize = 1024;

#[derive(Clone)]
struct Rule {
    prefix: String,
}

#[derive(Clone, Default)]
struct Ruleset {
    write_allow: Vec<Rule>,
    read_deny: Vec<Rule>,
}

pub struct Whitelist {
    rulesets: [Ruleset; 2],
    active: AtomicUsize,
}

impl Whitelist {
    pub fn new() -> Self {
        Self {
            rulesets: [Ruleset::default(), Ruleset::default()],
            active: AtomicUsize::new(0),
        }
    }

    /// Load rules from a config file into the active buffer.
    /// Call this for the initial load (before any `reload`).
    pub fn load(&mut self, path: &Path) -> io::Result<()> {
        let rs = parse_config(path)?;
        self.rulesets[0] = rs;
        self.active.store(0, Ordering::Release);
        Ok(())
    }

    /// Hot-reload: load rules into the inactive buffer, then atomically swap.
    pub fn reload(&mut self, path: &Path) -> io::Result<()> {
        let next = 1 - self.active.load(Ordering::Acquire);
        let rs = parse_config(path)?;
        self.rulesets[next] = rs;
        self.active.store(next, Ordering::Release);
        Ok(())
    }

    /// Check if a path is permitted for the given open flags.
    ///
    /// Read (O_RDONLY): blacklist — deny if in read_deny, else allow.
    /// Write (O_WRONLY/O_RDWR): whitelist — allow only if in write_allow.
    pub fn check_path(&self, path: &str, open_flags: i32) -> bool {
        let idx = self.active.load(Ordering::Acquire);
        let rs = &self.rulesets[idx];

        let accmode = open_flags & libc::O_ACCMODE;
        if accmode == libc::O_RDONLY {
            // Read: blacklist — deny if matched
            !prefix_match(&rs.read_deny, path)
        } else {
            // Write: whitelist — allow only if matched
            prefix_match(&rs.write_allow, path)
        }
    }

    /// Check if a path is in the write whitelist.
    /// Used by the expanded syscall handlers for non-openat write operations.
    pub fn is_write_allowed(&self, path: &str) -> bool {
        let idx = self.active.load(Ordering::Acquire);
        let rs = &self.rulesets[idx];
        prefix_match(&rs.write_allow, path)
    }

    /// Check if a path is in the read deny list.
    #[allow(dead_code)]
    pub fn is_read_denied(&self, path: &str) -> bool {
        let idx = self.active.load(Ordering::Acquire);
        let rs = &self.rulesets[idx];
        prefix_match(&rs.read_deny, path)
    }

    /// Get write-allow count (for logging).
    pub fn write_count(&self) -> usize {
        let idx = self.active.load(Ordering::Acquire);
        self.rulesets[idx].write_allow.len()
    }

    /// Get read-deny count (for logging).
    pub fn read_count(&self) -> usize {
        let idx = self.active.load(Ordering::Acquire);
        self.rulesets[idx].read_deny.len()
    }

    /// Return the list of write-allow prefixes (for Landlock).
    #[allow(dead_code)]
    pub fn write_paths(&self) -> Vec<String> {
        let idx = self.active.load(Ordering::Acquire);
        self.rulesets[idx]
            .write_allow
            .iter()
            .map(|r| r.prefix.clone())
            .collect()
    }
}

fn prefix_match(rules: &[Rule], path: &str) -> bool {
    rules.iter().any(|r| path.starts_with(&r.prefix))
}

fn parse_config(path: &Path) -> io::Result<Ruleset> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let mut rs = Ruleset::default();
    // 0 = no section, 1 = [write], 2 = [read]
    let mut section = 0;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line == "[write]" {
            section = 1;
            continue;
        }
        if line == "[read]" {
            section = 2;
            continue;
        }

        match section {
            1 => {
                if rs.write_allow.len() < MAX_RULES {
                    rs.write_allow.push(Rule {
                        prefix: line.to_string(),
                    });
                }
            }
            2 => {
                if rs.read_deny.len() < MAX_RULES {
                    rs.read_deny.push(Rule {
                        prefix: line.to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(rs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_config(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_basic_whitelist() {
        let cfg = temp_config(
            "[write]\n/tmp/\n/home/user/project/\n\n[read]\n/mnt/secret\n",
        );
        let mut wl = Whitelist::new();
        wl.load(cfg.path()).unwrap();

        assert_eq!(wl.write_count(), 2);
        assert_eq!(wl.read_count(), 1);

        // Write checks
        assert!(wl.check_path("/tmp/foo", libc::O_WRONLY));
        assert!(wl.check_path("/home/user/project/bar", libc::O_RDWR));
        assert!(!wl.check_path("/etc/passwd", libc::O_WRONLY));

        // Read checks
        assert!(wl.check_path("/etc/passwd", libc::O_RDONLY));
        assert!(!wl.check_path("/mnt/secret/file", libc::O_RDONLY));
    }

    #[test]
    fn test_is_write_allowed() {
        let cfg = temp_config("[write]\n/tmp/\n");
        let mut wl = Whitelist::new();
        wl.load(cfg.path()).unwrap();

        assert!(wl.is_write_allowed("/tmp/anything"));
        assert!(!wl.is_write_allowed("/var/anything"));
    }
}
