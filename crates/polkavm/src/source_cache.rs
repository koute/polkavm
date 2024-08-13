use alloc::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub struct SourceCache {
    cache: HashMap<String, Option<(String, Vec<usize>)>>,
    home_path: Option<Option<PathBuf>>,
    rustc_sources: Option<Vec<(String, PathBuf)>>,
}

impl SourceCache {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::unused_self)]
    fn home_path_uncached(&self) -> Option<PathBuf> {
        let buffer = std::env::var("HOME").ok()?;
        if buffer.is_empty() {
            return None;
        }

        Some(buffer.into())
    }

    fn rustc_sources_uncached(&mut self) -> Option<Vec<(String, PathBuf)>> {
        let mut list = Vec::new();
        let toolchains_path = {
            let mut buffer = self.home_path()?;
            buffer.push(".rustup");
            buffer.push("toolchains");
            buffer
        };

        let iter = match std::fs::read_dir(&toolchains_path) {
            Ok(iter) => iter,
            Err(error) => {
                log::warn!("Error reading {toolchains_path:?}: {error}");
                return None;
            }
        };

        for entry in iter {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    log::warn!("Error reading entry in {toolchains_path:?}: {error}");
                    continue;
                }
            };

            let root_path = entry.path();
            let rustc_path = {
                let mut buffer = root_path.clone();
                buffer.push("bin");
                buffer.push("rustc");
                buffer
            };

            if !rustc_path.exists() {
                continue;
            }

            let sources_path = {
                let mut buffer = root_path;
                buffer.push("lib");
                buffer.push("rustlib");
                buffer.push("src");
                buffer.push("rust");
                buffer
            };

            if !sources_path.exists() {
                continue;
            }

            let output = match std::process::Command::new(&rustc_path).args(["--version"]).output() {
                Ok(output) => output,
                Err(error) => {
                    log::warn!("Error extracting version from {rustc_path:?}: {error}");
                    continue;
                }
            };

            if !output.status.success() {
                log::warn!(
                    "Error extracting version from {rustc_path:?}: non successful status: {}",
                    output.status
                );
                continue;
            }

            let Ok(version_string) = String::from_utf8(output.stdout) else {
                log::warn!("Error extracting version from {rustc_path:?}: returned version is not valid UTF-8");
                continue;
            };

            // For example: "rustc 1.70.0-nightly (61863f31c 2023-08-15)"
            let p = &version_string[version_string.find('(')? + 1..];
            let p = &p[..p.find(' ')?];

            log::debug!("Found Rust sources for hash '{p}' at: {sources_path:?}");
            list.push((p.to_owned(), sources_path));
        }

        Some(list)
    }

    fn home_path(&mut self) -> Option<PathBuf> {
        if let Some(ref path) = self.home_path {
            return path.clone();
        }

        let result = self.home_path_uncached();
        if let Some(ref path) = result {
            log::debug!("Found HOME at: {path:?}");
        } else {
            log::debug!("HOME not found!");
        }
        self.home_path = Some(result.clone());
        result
    }

    fn rustc_sources(&mut self) -> &[(String, PathBuf)] {
        if self.rustc_sources.is_none() {
            self.rustc_sources = Some(self.rustc_sources_uncached().unwrap_or_default());
        }

        self.rustc_sources.as_ref().unwrap()
    }

    fn read_source_file(&mut self, path: &str) -> Option<String> {
        const HOME_PREFIX: &str = "~/";
        const RUSTC_PREFIX: &str = "/rustc/";
        let filesystem_path = if let Some(relative_path) = path.strip_prefix(HOME_PREFIX) {
            // Example of a path like this:
            //   "~/.cargo/registry/src/github.com-1ecc6299db9ec823/compiler_builtins-0.1.91/src/macros.rs"
            let mut buffer = self.home_path()?;
            buffer.push(relative_path);
            Cow::Owned(buffer)
        } else if let Some(relative_path) = path.strip_prefix(RUSTC_PREFIX) {
            // Example of a path like this:
            //   "/rustc/61863f31ccd4783186a5e839e6298d166d27368c/library/alloc/src/fmt.rs"
            let p = relative_path;
            let index = p.find('/')?;
            let hash = &p[..index];
            let relative_path = &p[index + 1..];
            if relative_path.is_empty() || hash.is_empty() {
                return None;
            }

            let sources = self.rustc_sources();
            let (_, sources_root) = sources.iter().find(|(sources_hash, _)| hash.starts_with(sources_hash))?;
            Cow::Owned(sources_root.join(relative_path))
        } else {
            Cow::Borrowed(Path::new(path))
        };

        match std::fs::read_to_string(&filesystem_path) {
            Ok(contents) => {
                log::debug!("Loaded source file: '{path}' (from {filesystem_path:?})");
                Some(contents)
            }
            Err(error) => {
                log::warn!("Failed to load source file '{path}' from {filesystem_path:?}: {error}");
                None
            }
        }
    }

    pub fn lookup_source_line(&mut self, path: &str, line: u32) -> Option<&str> {
        if !self.cache.contains_key(path) {
            let Some(contents) = self.read_source_file(path) else {
                self.cache.insert(path.to_owned(), None);
                return None;
            };

            let mut line_to_offset = Vec::new();
            line_to_offset.push(0);
            for (offset, byte) in contents.bytes().enumerate() {
                if byte == b'\n' {
                    line_to_offset.push(offset + 1);
                }
            }

            self.cache.insert(path.to_owned(), Some((contents, line_to_offset)));
        }

        let cached = self.cache.get(path)?;
        let (contents, line_to_offset) = cached.as_ref()?;
        let line = (line as usize).wrapping_sub(1);
        let offset = *line_to_offset.get(line)?;
        let next_offset = line_to_offset.get(line.wrapping_add(1)).copied().unwrap_or(contents.len());
        contents.get(offset..next_offset).map(|s| s.trim_end())
    }
}
