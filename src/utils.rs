// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// Provides general-purpose helper functions for the application.
pub struct Utility;

/// A configurable safe file reader with security validations.
pub struct SafeFileReader {
    max_size: Option<u64>,
    allowed_extensions: Option<Vec<String>>,
    allowed_base_dir: Option<PathBuf>,
}

impl Utility {
    /// Formats a raw byte count into a human-readable file size string.
    ///
    /// Automatically scales the output to the most appropriate unit (B, KB, MB, GB, or TB)
    /// and formats the value to two decimal places.
    ///
    /// # Arguments
    /// * `size` - The file size in raw bytes (`u64`).
    ///
    /// # Returns
    /// A formatted string representing the size (e.g., "1.50 MB").
    pub fn format_file_size(size: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        const TB: u64 = GB * 1024;

        if size < KB {
            format!("{size} B")
        } else if size < MB {
            format!("{:.2} KB", size as f64 / KB as f64)
        } else if size < GB {
            format!("{:.2} MB", size as f64 / MB as f64)
        } else if size < TB {
            format!("{:.2} GB", size as f64 / GB as f64)
        } else {
            format!("{:.2} TB", size as f64 / TB as f64)
        }
    }
}

impl SafeFileReader {
    pub fn new() -> Self {
        Self {
            max_size: None,
            allowed_extensions: None,
            allowed_base_dir: None,
        }
    }

    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    pub fn allowed_extensions(mut self, extensions: Vec<&str>) -> Self {
        self.allowed_extensions = Some(extensions.iter().map(|e| e.to_lowercase()).collect());
        self
    }

    pub fn allowed_base_dir(mut self, dir: &str) -> Self {
        self.allowed_base_dir = Some(PathBuf::from(dir));
        self
    }

    pub fn read(&self, file_path: &str) -> Result<String> {
        let path = Path::new(file_path)
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("Invalid file path '{}': {}", file_path, e))?;

        // Check: is it a file?
        if !path.is_file() {
            bail!("'{}' is not a file", file_path);
        }

        // Check: allowed extensions
        if let Some(ref allowed) = self.allowed_extensions {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_lowercase())
                .unwrap_or_default();

            if !allowed.contains(&ext) {
                bail!(
                    "File '{}' has extension '.{}', but only [{}] are allowed",
                    file_path,
                    ext,
                    allowed.join(", ")
                );
            }
        }

        // Check: allowed base directory
        if let Some(ref base_dir) = self.allowed_base_dir {
            let canonical_base = base_dir.canonicalize().map_err(|e| {
                anyhow::anyhow!("Invalid base directory '{}': {}", base_dir.display(), e)
            })?;

            if !path.starts_with(&canonical_base) {
                bail!(
                    "Access denied: '{}' is outside the allowed directory '{}'",
                    file_path,
                    canonical_base.display()
                );
            }
        }

        // Check: file size
        if let Some(max) = self.max_size {
            let metadata = std::fs::metadata(&path)
                .map_err(|e| anyhow::anyhow!("Cannot access '{}': {}", file_path, e))?;

            if metadata.len() > max {
                bail!(
                    "File '{}' is too large ({}). Maximum allowed size is {}",
                    file_path,
                    Utility::format_file_size(metadata.len()),
                    Utility::format_file_size(max)
                );
            }
        }

        std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("Failed to read '{}': {}", path.display(), e))
    }
}

impl Default for SafeFileReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_read_file_valid() {
        // Test JSON file
        let mut tmp_json = tempfile::NamedTempFile::new().unwrap();
        write!(tmp_json, r#"{{"server":"s1"}}"#).unwrap();
        let path_json = tmp_json.path().to_str().unwrap();

        let reader = SafeFileReader::new();
        let result_json = reader.read(path_json).unwrap();
        assert_eq!(result_json, r#"{"server":"s1"}"#);

        // Test plain text file
        let mut tmp_text = tempfile::NamedTempFile::new().unwrap();
        write!(tmp_text, "just some plain text data").unwrap();
        let path_text = tmp_text.path().to_str().unwrap();

        let result_text = reader.read(path_text).unwrap();
        assert_eq!(result_text, "just some plain text data");
    }

    #[test]
    fn test_read_file_too_large() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "hello world").unwrap(); // 11 bytes
        let path = tmp.path().to_str().unwrap();

        let reader = SafeFileReader::new().max_size(5);
        let result = reader.read(path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_allowed_extensions() {
        // Test valid extension
        let mut tmp_valid = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        write!(tmp_valid, r#"{{"server":"s1"}}"#).unwrap();
        let path_valid = tmp_valid.path().to_str().unwrap();

        let reader = SafeFileReader::new().allowed_extensions(vec!["json", "yaml"]);
        let result_valid = reader.read(path_valid).unwrap();
        assert_eq!(result_valid, r#"{"server":"s1"}"#);

        // Test invalid extension
        let mut tmp_invalid = tempfile::Builder::new().suffix(".txt").tempfile().unwrap();
        write!(tmp_invalid, "some text").unwrap();
        let path_invalid = tmp_invalid.path().to_str().unwrap();

        let reader_invalid = SafeFileReader::new().allowed_extensions(vec!["json", "yaml"]);
        let result_invalid = reader_invalid.read(path_invalid);
        assert!(result_invalid.is_err());
        assert!(
            result_invalid
                .unwrap_err()
                .to_string()
                .contains("only [json, yaml] are allowed")
        );
    }

    #[test]
    fn test_allowed_base_dir() {
        // Test valid base dir
        let tmp_dir = tempfile::tempdir().unwrap();
        let file_path = tmp_dir.path().join("test.json");
        let mut file = std::fs::File::create(&file_path).unwrap();
        write!(file, r#"{{"server":"s1"}}"#).unwrap();

        let reader = SafeFileReader::new().allowed_base_dir(tmp_dir.path().to_str().unwrap());
        let result = reader.read(file_path.to_str().unwrap()).unwrap();
        assert_eq!(result, r#"{"server":"s1"}"#);

        // Test invalid base dir
        let other_dir = tempfile::tempdir().unwrap();
        let reader_invalid =
            SafeFileReader::new().allowed_base_dir(other_dir.path().to_str().unwrap());
        let result_invalid = reader_invalid.read(file_path.to_str().unwrap());
        assert!(result_invalid.is_err());
        assert!(
            result_invalid
                .unwrap_err()
                .to_string()
                .contains("Access denied")
        );
    }
}
