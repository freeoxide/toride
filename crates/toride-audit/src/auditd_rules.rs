//! Audit rule management.
//!
//! Provides functions for reading, writing, and managing audit rule files
//! in `/etc/audit/rules.d/`.

use std::fs;

use crate::paths::{secure_dir_mode, secure_file_mode, validate_name};
use crate::{AuditPaths, Error, Result};

// ---------------------------------------------------------------------------
// AuditRuleFile
// ---------------------------------------------------------------------------

/// Represents an audit rules file in `/etc/audit/rules.d/`.
#[derive(Debug, Clone)]
pub struct AuditRuleFile {
    /// File name (without directory).
    pub name: String,
    /// Raw content of the rules file.
    pub content: String,
}

impl AuditRuleFile {
    /// Parse the content into individual rule lines.
    ///
    /// Filters out empty lines and comments.
    #[must_use]
    pub fn rules(&self) -> Vec<&str> {
        self.content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#')
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rule management functions
// ---------------------------------------------------------------------------

/// List all audit rule files in the rules directory.
///
/// Returns files with the `.rules` extension, sorted alphabetically.
///
/// # Errors
///
/// Returns [`Error::Io`] if the directory cannot be read.
pub fn list_rule_files(paths: &AuditPaths) -> Result<Vec<AuditRuleFile>> {
    if !paths.rules_d.exists() {
        return Ok(Vec::new());
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(&paths.rules_d)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "rules") {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let content = fs::read_to_string(&path)?;
            files.push(AuditRuleFile { name, content });
        }
    }

    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(files)
}

/// Read a specific audit rule file by name.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be read.
pub fn read_rule_file(paths: &AuditPaths, name: &str) -> Result<AuditRuleFile> {
    validate_name(name)?;
    let path = paths.rules_path(name);
    let content = fs::read_to_string(&path)?;
    Ok(AuditRuleFile {
        name: name.to_owned(),
        content,
    })
}

/// Write an audit rule file, creating a backup first.
///
/// # Errors
///
/// Returns [`Error::ConfigWrite`] if the file cannot be written.
pub fn write_rule_file(paths: &AuditPaths, name: &str, content: &str) -> Result<()> {
    validate_name(name)?;
    let path = paths.rules_path(name);

    if path.exists() {
        crate::backup::create_backup(&path)?;
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        secure_dir_mode(parent)?;
    }

    fs::write(&path, content).map_err(|e| Error::ConfigWrite(format!("{e}")))?;
    // Pin restrictive mode regardless of umask: audit rules drive security
    // observability and must never be group/other writable.
    secure_file_mode(&path)?;
    Ok(())
}

/// Remove an audit rule file.
///
/// Creates a backup before removing.
///
/// # Errors
///
/// Returns [`Error::Io`] if the file cannot be removed.
pub fn remove_rule_file(paths: &AuditPaths, name: &str) -> Result<()> {
    validate_name(name)?;
    let path = paths.rules_path(name);

    if path.exists() {
        crate::backup::create_backup(&path)?;
        fs::remove_file(&path)?;
    }

    Ok(())
}

/// Merge multiple rule files into a single sorted list of rules.
///
/// Deduplicates rules and sorts them for deterministic output.
#[must_use]
pub fn merge_rules(files: &[AuditRuleFile]) -> Vec<String> {
    let mut rules: Vec<String> = files
        .iter()
        .flat_map(|f| {
            f.content
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    !trimmed.is_empty() && !trimmed.starts_with('#')
                })
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
        })
        .collect();

    rules.sort();
    rules.dedup();
    rules
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_rule_file_rules_filters_comments_and_empty_lines() {
        let file = AuditRuleFile {
            name: "test".to_owned(),
            content: "# header comment\n\n-w /etc/passwd -p wa -k identity\n-a always,exit -S open -k test\n\n# trailing comment\n".to_owned(),
        };
        let rules = file.rules();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], "-w /etc/passwd -p wa -k identity");
        assert_eq!(rules[1], "-a always,exit -S open -k test");
    }

    #[test]
    fn audit_rule_file_rules_all_rules() {
        let file = AuditRuleFile {
            name: "all_rules".to_owned(),
            content: "-w /etc/passwd -p wa -k identity\n-w /etc/shadow -p wa -k identity"
                .to_owned(),
        };
        let rules = file.rules();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn audit_rule_file_rules_only_comments() {
        let file = AuditRuleFile {
            name: "comments".to_owned(),
            content: "# just comments\n# another comment\n".to_owned(),
        };
        let rules = file.rules();
        assert!(rules.is_empty());
    }

    #[test]
    fn merge_rules_deduplicates_and_sorts() {
        let files = vec![
            AuditRuleFile {
                name: "first".to_owned(),
                content: "-w /etc/shadow -p wa -k identity\n-w /etc/passwd -p wa -k identity"
                    .to_owned(),
            },
            AuditRuleFile {
                name: "second".to_owned(),
                content: "-w /etc/passwd -p wa -k identity\n-a always,exit -S open -k test"
                    .to_owned(),
            },
        ];
        let merged = merge_rules(&files);
        // Should be sorted and deduplicated.
        assert_eq!(merged.len(), 3);
        assert!(
            merged.windows(2).all(|w| w[0] <= w[1]),
            "merged rules must be sorted"
        );
        // /etc/passwd appears only once.
        assert_eq!(
            merged
                .iter()
                .filter(|r| **r == "-w /etc/passwd -p wa -k identity")
                .count(),
            1
        );
    }

    #[test]
    fn merge_rules_empty_files() {
        let files: Vec<AuditRuleFile> = vec![];
        let merged = merge_rules(&files);
        assert!(merged.is_empty());
    }

    #[test]
    fn merge_rules_skips_comments_and_empty_lines() {
        let files = vec![AuditRuleFile {
            name: "mixed".to_owned(),
            content: "# comment\n\n-w /etc/passwd -p wa -k identity\n".to_owned(),
        }];
        let merged = merge_rules(&files);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], "-w /etc/passwd -p wa -k identity");
    }
}
