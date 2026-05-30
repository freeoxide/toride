//! Privacy-aware redaction for status output.
//!
//! The status subsystem collects potentially sensitive information such as
//! hostnames, MAC addresses, serial numbers, and command-line arguments.  To
//! prevent accidental leaks when the data is displayed or logged, every piece
//! of identifying information is passed through a [`Redactor`] that strips or
//! masks values according to the active [`PrivacyMode`].
//!
//! # Privacy modes
//!
//! | Mode            | Hostname | MAC / Serial | Command-line | Username |
//! |-----------------|----------|--------------|--------------|----------|
//! | `Safe` (default)| hidden   | hidden       | hidden       | hidden   |
//! | `Diagnostics`   | shown    | hidden       | name only    | hidden   |
//! | `Full`          | shown    | shown        | shown        | shown    |
//!
//! The default is `Safe`, so callers that forget to configure privacy still
//! get a safe output.

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
    pub fn new(mode: PrivacyMode) -> Self {
        Self { mode }
    }

    /// Redact a hostname.
    ///
    /// * `Safe` -- returns `"[redacted]"`.
    /// * `Diagnostics` / `Full` -- returns the original value.
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
    pub fn should_show_username(&self) -> bool {
        self.mode == PrivacyMode::Full
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
    // Default / serialization
    // ------------------------------------------------------------------

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
