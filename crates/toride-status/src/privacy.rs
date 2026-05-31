//! Privacy-aware redaction for status output.
//!
//! The status subsystem collects potentially sensitive information such as
//! hostnames, MAC addresses, serial numbers, and command-line arguments.  To
//! prevent accidental leaks when the data is displayed or logged, every piece
//! of identifying information is passed through a [`Redactor`] that strips or
//! masks values according to the active [`PrivacyMode`].
//!
//! # Privacy mode comparison
//!
//! | Mode            | Hostname    | MAC / Serial | Command-line | Username    |
//! |-----------------|-------------|--------------|--------------|-------------|
//! | `Safe` (default)| `[redacted]`| `[redacted]` | `[redacted]` | `[redacted]`|
//! | `Diagnostics`   | shown       | `[redacted]` | name only    | `[redacted]`|
//! | `Full`          | shown       | shown        | shown        | shown       |
//!
//! The default is `Safe`, so callers that forget to configure privacy still
//! get a safe output.
//!
//! # Examples
//!
//! Redacting sensitive data for logging:
//!
//! ```
//! use toride_status::privacy::{PrivacyMode, Redactor};
//!
//! let redactor = Redactor::new(PrivacyMode::Safe);
//! assert_eq!(redactor.redact_hostname("my-host.local"), "[redacted]");
//! assert_eq!(redactor.redact_mac("AA:BB:CC:DD:EE:FF"), "[redacted]");
//! ```
//!
//! Using diagnostics mode for troubleshooting:
//!
//! ```
//! use toride_status::privacy::{PrivacyMode, Redactor};
//!
//! let redactor = Redactor::new(PrivacyMode::Diagnostics);
//! assert_eq!(redactor.redact_hostname("my-host.local"), "my-host.local");
//! assert_eq!(redactor.redact_command_line("/usr/bin/sshd -D -R -p 22"), "/usr/bin/sshd");
//! ```
//!
//! Full mode for local debugging:
//!
//! ```
//! use toride_status::privacy::{PrivacyMode, Redactor};
//!
//! let redactor = Redactor::new(PrivacyMode::Full);
//! assert_eq!(redactor.redact_serial("C02X12345678"), "C02X12345678");
//! assert!(redactor.should_show_username());
//! ```

use serde::Serialize;

/// Controls the level of detail exposed in status output.
///
/// `Safe` is the default and should be used unless the caller explicitly
/// opts in to richer diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub enum PrivacyMode {
    /// Redact all sensitive data (default).
    #[default]
    Safe,
    /// Show diagnostic data (hostnames, MACs) but not secrets.
    Diagnostics,
    /// Show everything.
    Full,
}

/// Applies redaction rules to sensitive strings based on the active
/// [`PrivacyMode`].
///
/// Construct with [`Redactor::new`] and then call individual `redact_*`
/// methods on each field before including it in output.
pub struct Redactor {
    mode: PrivacyMode,
}

impl Redactor {
    /// Create a new redactor that applies rules for the given `mode`.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let redactor = Redactor::new(PrivacyMode::Safe);
    /// ```
    #[must_use]
    pub const fn new(mode: PrivacyMode) -> Self {
        Self { mode }
    }

    /// Redact a hostname.
    ///
    /// * `Safe` -- returns `"[redacted]"`.
    /// * `Diagnostics` / `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let safe = Redactor::new(PrivacyMode::Safe);
    /// assert_eq!(safe.redact_hostname("my-host.local"), "[redacted]");
    ///
    /// let diag = Redactor::new(PrivacyMode::Diagnostics);
    /// assert_eq!(diag.redact_hostname("my-host.local"), "my-host.local");
    /// ```
    #[must_use]
    pub fn redact_hostname(&self, hostname: &str) -> String {
        match self.mode {
            PrivacyMode::Safe => "[redacted]".to_string(),
            _ => hostname.to_string(),
        }
    }

    /// Redact a MAC address.
    ///
    /// * `Safe` / `Diagnostics` -- returns `"[redacted]"`.
    /// * `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let redactor = Redactor::new(PrivacyMode::Diagnostics);
    /// assert_eq!(redactor.redact_mac("AA:BB:CC:DD:EE:FF"), "[redacted]");
    ///
    /// let full = Redactor::new(PrivacyMode::Full);
    /// assert_eq!(full.redact_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF");
    /// ```
    #[must_use]
    pub fn redact_mac(&self, mac: &str) -> String {
        match self.mode {
            PrivacyMode::Safe | PrivacyMode::Diagnostics => "[redacted]".to_string(),
            PrivacyMode::Full => mac.to_string(),
        }
    }

    /// Redact a hardware serial number.
    ///
    /// * `Safe` / `Diagnostics` -- returns `"[redacted]"`.
    /// * `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let redactor = Redactor::new(PrivacyMode::Safe);
    /// assert_eq!(redactor.redact_serial("C02X12345678"), "[redacted]");
    /// ```
    #[must_use]
    pub fn redact_serial(&self, serial: &str) -> String {
        match self.mode {
            PrivacyMode::Safe | PrivacyMode::Diagnostics => "[redacted]".to_string(),
            PrivacyMode::Full => serial.to_string(),
        }
    }

    /// Redact a command-line string.
    ///
    /// * `Safe` -- returns `"[redacted]"`.
    /// * `Diagnostics` -- returns only the command name (first token).
    /// * `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let safe = Redactor::new(PrivacyMode::Safe);
    /// assert_eq!(safe.redact_command_line("/usr/bin/sshd -D -R -p 22"), "[redacted]");
    ///
    /// let diag = Redactor::new(PrivacyMode::Diagnostics);
    /// assert_eq!(diag.redact_command_line("/usr/bin/sshd -D -R -p 22"), "/usr/bin/sshd");
    /// ```
    #[must_use]
    pub fn redact_command_line(&self, cmd: &str) -> String {
        match self.mode {
            PrivacyMode::Safe => "[redacted]".to_string(),
            PrivacyMode::Diagnostics => {
                // Show command name but redact arguments
                cmd.split_whitespace()
                    .next()
                    .unwrap_or("[redacted]")
                    .to_string()
            }
            PrivacyMode::Full => cmd.to_string(),
        }
    }

    /// Returns `true` when the current mode permits showing usernames.
    ///
    /// Only returns `true` in [`PrivacyMode::Full`] mode.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let safe = Redactor::new(PrivacyMode::Safe);
    /// assert!(!safe.should_show_username());
    ///
    /// let full = Redactor::new(PrivacyMode::Full);
    /// assert!(full.should_show_username());
    /// ```
    #[must_use]
    pub fn should_show_username(&self) -> bool {
        self.mode == PrivacyMode::Full
    }

    /// Redact a UUID string.
    ///
    /// * `Safe` / `Diagnostics` -- returns `"[redacted]"`.
    /// * `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let safe = Redactor::new(PrivacyMode::Safe);
    /// assert_eq!(safe.redact_uuid("550e8400-e29b-41d4-a716-446655440000"), "[redacted]");
    ///
    /// let full = Redactor::new(PrivacyMode::Full);
    /// assert_eq!(full.redact_uuid("550e8400-e29b-41d4-a716-446655440000"), "550e8400-e29b-41d4-a716-446655440000");
    /// ```
    #[must_use]
    pub fn redact_uuid(&self, uuid: &str) -> String {
        match self.mode {
            PrivacyMode::Safe | PrivacyMode::Diagnostics => "[redacted]".to_string(),
            PrivacyMode::Full => uuid.to_string(),
        }
    }

    /// Redact a hardware asset tag.
    ///
    /// * `Safe` / `Diagnostics` -- returns `"[redacted]"`.
    /// * `Full` -- returns the original value.
    ///
    /// # Examples
    ///
    /// ```
    /// use toride_status::privacy::{PrivacyMode, Redactor};
    ///
    /// let safe = Redactor::new(PrivacyMode::Safe);
    /// assert_eq!(safe.redact_asset_tag("ASSET-001234"), "[redacted]");
    ///
    /// let full = Redactor::new(PrivacyMode::Full);
    /// assert_eq!(full.redact_asset_tag("ASSET-001234"), "ASSET-001234");
    /// ```
    #[must_use]
    pub fn redact_asset_tag(&self, tag: &str) -> String {
        match self.mode {
            PrivacyMode::Safe | PrivacyMode::Diagnostics => "[redacted]".to_string(),
            PrivacyMode::Full => tag.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Hostname
    // ------------------------------------------------------------------

    #[test]
    fn safe_mode_redacts_hostname() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert_eq!(r.redact_hostname("my-host.local"), "[redacted]");
    }

    #[test]
    fn diagnostics_mode_shows_hostname() {
        let r = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(r.redact_hostname("my-host.local"), "my-host.local");
    }

    #[test]
    fn full_mode_shows_hostname() {
        let r = Redactor::new(PrivacyMode::Full);
        assert_eq!(r.redact_hostname("my-host.local"), "my-host.local");
    }

    // ------------------------------------------------------------------
    // MAC address
    // ------------------------------------------------------------------

    #[test]
    fn safe_mode_redacts_mac() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert_eq!(r.redact_mac("AA:BB:CC:DD:EE:FF"), "[redacted]");
    }

    #[test]
    fn diagnostics_mode_redacts_mac() {
        let r = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(r.redact_mac("AA:BB:CC:DD:EE:FF"), "[redacted]");
    }

    #[test]
    fn full_mode_shows_mac() {
        let r = Redactor::new(PrivacyMode::Full);
        assert_eq!(r.redact_mac("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF");
    }

    // ------------------------------------------------------------------
    // Serial number
    // ------------------------------------------------------------------

    #[test]
    fn safe_mode_redacts_serial() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert_eq!(r.redact_serial("C02X12345678"), "[redacted]");
    }

    #[test]
    fn full_mode_shows_serial() {
        let r = Redactor::new(PrivacyMode::Full);
        assert_eq!(r.redact_serial("C02X12345678"), "C02X12345678");
    }

    // ------------------------------------------------------------------
    // Command line
    // ------------------------------------------------------------------

    #[test]
    fn safe_mode_redacts_command_line() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert_eq!(
            r.redact_command_line("/usr/bin/sshd -D -R -p 22"),
            "[redacted]"
        );
    }

    #[test]
    fn diagnostics_mode_shows_command_name_only() {
        let r = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(
            r.redact_command_line("/usr/bin/sshd -D -R -p 22"),
            "/usr/bin/sshd"
        );
    }

    #[test]
    fn full_mode_shows_command_line() {
        let r = Redactor::new(PrivacyMode::Full);
        let cmd = "/usr/bin/sshd -D -R -p 22";
        assert_eq!(r.redact_command_line(cmd), cmd);
    }

    // ------------------------------------------------------------------
    // Hostname edge cases
    // ------------------------------------------------------------------

    #[test]
    fn redact_hostname_empty_string() {
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_hostname(""), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_hostname(""), "");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_hostname(""), "");
    }

    #[test]
    fn redact_hostname_very_long() {
        let long_hostname = "a".repeat(256);
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_hostname(&long_hostname), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_hostname(&long_hostname), long_hostname);
    }

    #[test]
    fn redact_hostname_unicode() {
        let hostname = "host-\u{00e9}\u{00e8}\u{00ea}-\u{4e16}\u{754c}";
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_hostname(hostname), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_hostname(hostname), hostname);

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_hostname(hostname), hostname);
    }

    // ------------------------------------------------------------------
    // MAC address edge cases
    // ------------------------------------------------------------------

    #[test]
    fn redact_mac_empty_string() {
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_mac(""), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_mac(""), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_mac(""), "");
    }

    #[test]
    fn redact_mac_invalid_format() {
        let invalid = "not-a-mac";
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_mac(invalid), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_mac(invalid), invalid);
    }

    #[test]
    fn redact_mac_lowercase() {
        let mac = "aa:bb:cc:dd:ee:ff";
        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_mac(mac), mac);
    }

    // ------------------------------------------------------------------
    // Serial number edge cases
    // ------------------------------------------------------------------

    #[test]
    fn redact_serial_empty_string() {
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_serial(""), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_serial(""), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_serial(""), "");
    }

    #[test]
    fn redact_serial_very_long() {
        let long_serial = "X".repeat(256);
        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_serial(&long_serial), long_serial);

        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_serial(&long_serial), "[redacted]");
    }

    #[test]
    fn redact_serial_special_characters() {
        let serial = "SN-123/456@#$%";
        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_serial(serial), serial);

        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_serial(serial), "[redacted]");
    }

    // ------------------------------------------------------------------
    // Command line edge cases
    // ------------------------------------------------------------------

    #[test]
    fn redact_command_line_empty_string() {
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_command_line(""), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line(""), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line(""), "");
    }

    #[test]
    fn redact_command_line_only_spaces() {
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_command_line("   "), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line("   "), "[redacted]");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line("   "), "   ");
    }

    #[test]
    fn redact_command_line_single_word() {
        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line("python"), "python");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line("python"), "python");
    }

    #[test]
    fn redact_command_line_path_with_spaces() {
        let cmd = "/Program Files/app --flag";
        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line(cmd), "/Program");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line(cmd), cmd);
    }

    #[test]
    fn redact_command_line_very_long() {
        let long_cmd = format!("binary {}", "arg ".repeat(500));
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_command_line(&long_cmd), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line(&long_cmd), "binary");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line(&long_cmd), long_cmd);
    }

    #[test]
    fn redact_command_line_special_characters() {
        let cmd = "cmd --opt='hello world' --flag;rm -rf /";
        let safe = Redactor::new(PrivacyMode::Safe);
        assert_eq!(safe.redact_command_line(cmd), "[redacted]");

        let diag = Redactor::new(PrivacyMode::Diagnostics);
        assert_eq!(diag.redact_command_line(cmd), "cmd");

        let full = Redactor::new(PrivacyMode::Full);
        assert_eq!(full.redact_command_line(cmd), cmd);
    }

    // ------------------------------------------------------------------
    // Default / serialization
    // ------------------------------------------------------------------

    #[test]
    fn should_show_username_safe() {
        let r = Redactor::new(PrivacyMode::Safe);
        assert!(!r.should_show_username());
    }

    #[test]
    fn should_show_username_diagnostics() {
        let r = Redactor::new(PrivacyMode::Diagnostics);
        assert!(!r.should_show_username());
    }

    #[test]
    fn should_show_username_full() {
        let r = Redactor::new(PrivacyMode::Full);
        assert!(r.should_show_username());
    }

    #[test]
    fn default_is_safe() {
        assert_eq!(PrivacyMode::default(), PrivacyMode::Safe);
    }

    #[test]
    fn serialize_privacy_mode() {
        let json = serde_json::to_string(&PrivacyMode::Safe).unwrap();
        assert_eq!(json, "\"Safe\"");

        let json = serde_json::to_string(&PrivacyMode::Diagnostics).unwrap();
        assert_eq!(json, "\"Diagnostics\"");

        let json = serde_json::to_string(&PrivacyMode::Full).unwrap();
        assert_eq!(json, "\"Full\"");
    }
}
