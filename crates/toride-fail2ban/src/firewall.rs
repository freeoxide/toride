//! Firewall diagnostics module.
//!
//! Mostly diagnostic in v1 -- does **not** manually insert firewall rules.
//! The [`FirewallChecker`] inspects whether the tools and structures required
//! by the configured Fail2Ban actions are actually present on the host.
//!
//! # Checks performed
//!
//! - `nft` binary availability when nftables actions are configured
//! - `iptables` / `ip6tables` binary availability when iptables actions are
//!   configured
//! - Existence of the expected nft sets (`nft list set inet fail2ban <name>`)
//! - Existence of the expected iptables chains (`iptables -n -L <chain>`)
//! - IPv6 ban support when IPv6 addresses are in use
//!
//! All commands go through the [`Runner`] trait. No
//! direct `std::process::Command` calls are made anywhere in this module.
//!
//! # Feature flags (planned deep-inspection backends)
//!
//! - **`firewall-nft`**: Enables native nftables JSON ruleset inspection.  When
//!   implemented, `FirewallChecker::inspect_nft_ruleset_json` will parse the
//!   full nftables ruleset returned by `nft -j list ruleset` into structured
//!   Rust types, allowing programmatic verification of ban rules without shelling
//!   out to `nft` for each individual query.  **Not yet implemented.**
//!
//! - **`firewall-iptables`**: Enables native iptables rules parsing.  When
//!   implemented, `FirewallChecker::inspect_iptables_rules` will parse
//!   `iptables-save` output (or equivalent) into structured rule representations,
//!   enabling offline analysis of ban chains and jump targets.  **Not yet
//!   implemented.**

#[cfg(any(feature = "firewall-nft", feature = "firewall-iptables"))]
use crate::Error;
use crate::Result;
use crate::command::Runner;
use crate::report::{Finding, Severity};

/// Table family and table used by Fail2Ban's stock nftables actions
/// (`table_family = inet`, `table = f2b-table` in `action.d/nftables.conf`).
const NFT_TABLE_FAMILY: &str = "inet";
const NFT_TABLE: &str = "f2b-table";

/// Prefix of the nft set names Fail2Ban's stock nftables actions create
/// (`addr_set = addr-set-<name>` for IPv4, `addr6-set-<name>` for IPv6).
const NFT_SET_PREFIX: &str = "addr-set-";
const NFT_SET_PREFIX_V6: &str = "addr6-set-";

/// Prefix of the iptables chains Fail2Ban's stock iptables actions create
/// (`actionban = <iptables> -I f2b-<name> 1 -s <ip> -j DROP`).
const IPTABLES_CHAIN_PREFIX: &str = "f2b-";

/// Expected nft set name for a jail (`addr-set-<jail>`).
#[must_use]
pub fn nft_set_name_for_jail(jail: &str) -> String {
    format!("{NFT_SET_PREFIX}{jail}")
}

/// Expected nft IPv6 set name for a jail (`addr6-set-<jail>`).
#[must_use]
pub fn nft_set6_name_for_jail(jail: &str) -> String {
    format!("{NFT_SET_PREFIX_V6}{jail}")
}

/// Expected iptables chain name for a jail (`f2b-<jail>`).
#[must_use]
pub fn iptables_chain_name_for_jail(jail: &str) -> String {
    format!("{IPTABLES_CHAIN_PREFIX}{jail}")
}

/// Diagnostic checker for firewall backend availability.
///
/// Borrows a [`Runner`] implementation so it can be used with either the
/// production [`DuctRunner`](crate::command::DuctRunner) or the test
/// [`FakeRunner`](crate::command::FakeRunner).
///
/// # Example
///
/// ```ignore
/// use toride_fail2ban::command::DuctRunner;
/// use toride_fail2ban::firewall::FirewallChecker;
///
/// let runner = DuctRunner::new();
/// let checker = FirewallChecker::new(&runner);
///
/// let findings = checker.diagnose(&["nftables".to_string()]);
/// for f in &findings {
///     println!("[{}] {}", f.severity, f.title);
/// }
/// ```
pub struct FirewallChecker<'a> {
    runner: &'a dyn Runner,
}

impl<'a> FirewallChecker<'a> {
    /// Create a new checker that delegates command execution to `runner`.
    pub fn new(runner: &'a dyn Runner) -> Self {
        Self { runner }
    }

    /// Check whether the `nft` binary is available on the system.
    ///
    /// Runs `nft --version` and returns `true` if the command exits
    /// successfully. Returns `Ok(false)` if the command fails (binary not
    /// found, permission denied, etc.).
    pub fn check_nft_available(&self) -> Result<bool> {
        Ok(self.runner.run("nft", &["--version"])?.success)
    }

    /// Check whether the `iptables` binary is available on the system.
    ///
    /// Runs `iptables --version` and returns `true` on success.
    pub fn check_iptables_available(&self) -> Result<bool> {
        Ok(self.runner.run("iptables", &["--version"])?.success)
    }

    /// Check whether the `ip6tables` binary is available on the system.
    ///
    /// Runs `ip6tables --version` and returns `true` on success.
    pub fn check_ip6tables_available(&self) -> Result<bool> {
        Ok(self.runner.run("ip6tables", &["--version"])?.success)
    }

    /// Check whether an nft set exists in the Fail2Ban table.
    ///
    /// Runs `nft list set inet f2b-table <set_name>` and returns `true` if
    /// the command succeeds (i.e. the set is present in the kernel).
    pub fn check_nft_set(&self, set_name: &str) -> Result<bool> {
        let args = &["list", "set", NFT_TABLE_FAMILY, NFT_TABLE, set_name];
        Ok(self.runner.run("nft", args)?.success)
    }

    /// Check whether the nft sets a jail's stock nftables action creates
    /// exist: `addr-set-<jail>` and `addr6-set-<jail>` in `inet f2b-table`.
    pub fn check_nft_sets_for_jail(&self, jail: &str) -> Result<(bool, bool)> {
        let v4 = self.check_nft_set(&nft_set_name_for_jail(jail))?;
        let v6 = self.check_nft_set(&nft_set6_name_for_jail(jail))?;
        Ok((v4, v6))
    }

    /// Check whether an iptables chain exists.
    ///
    /// Runs `iptables -n -L <chain>` and returns `true` if the command
    /// succeeds.
    pub fn check_iptables_chain(&self, chain: &str) -> Result<bool> {
        let args = &["-n", "-L", chain];
        Ok(self.runner.run("iptables", args)?.success)
    }

    /// Run all firewall-related diagnostic checks based on the configured
    /// actions and return a list of [`Finding`] values.
    ///
    /// `configured_actions` should contain the action names as they appear in
    /// the Fail2Ban jail configuration (e.g. `"nftables"`, `"iptables"`,
    /// `"iptables-multiport"`, `"nftables-multiport"`); `jails` names the
    /// jails those actions run for, because stock Fail2Ban actions create
    /// per-jail structures (`addr-set-<jail>` nft sets, `f2b-<jail>`
    /// iptables chains).
    ///
    /// # Checks performed
    ///
    /// 1. If any action contains `"nftables"`, verify `nft` is available and
    ///    each jail's `addr-set-<jail>` / `addr6-set-<jail>` sets exist.
    /// 2. If any action contains `"iptables"`, verify `iptables` is available
    ///    and each jail's `f2b-<jail>` chain exists.
    /// 3. If any action contains `"iptables"` (which implies potential IPv6
    ///    usage), verify `ip6tables` is available as well.
    /// 4. If no firewall-related action is found at all, emit an informational
    ///    note that firewall diagnostics were skipped.
    pub fn diagnose(&self, jails: &[String], configured_actions: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let uses_nft = configured_actions
            .iter()
            .any(|a| a.to_ascii_lowercase().contains("nftables"));

        let uses_iptables = configured_actions
            .iter()
            .any(|a| a.to_ascii_lowercase().contains("iptables"));

        // If no firewall-related actions are configured, emit a single info
        // finding and return early.
        if !uses_nft && !uses_iptables {
            findings.push(
                Finding::new(
                    "firewall.no-firewall-action",
                    Severity::Info,
                    "No firewall action configured",
                )
                .detail(
                    "None of the configured actions reference nftables or \
                     iptables. Firewall backend checks were skipped.",
                ),
            );
            return findings;
        }

        if uses_nft {
            self.diagnose_nftables(jails, &mut findings);
        }

        if uses_iptables {
            self.diagnose_iptables(jails, &mut findings);
        }

        findings
    }

    /// Run nftables-specific diagnostic probes and append findings, one set
    /// of checks per jail (`addr-set-<jail>` and `addr6-set-<jail>`).
    fn diagnose_nftables(&self, jails: &[String], findings: &mut Vec<Finding>) {
        match self.check_nft_available() {
            Ok(true) => {
                let jails_to_check: Vec<String> = if jails.is_empty() {
                    Vec::new()
                } else {
                    jails.to_vec()
                };
                for jail in &jails_to_check {
                    match self.check_nft_sets_for_jail(jail) {
                        Ok((true, _)) => {
                            findings.push(Finding::new(
                                "firewall.nft.set-present",
                                Severity::Ok,
                                format!("nft set for jail '{jail}' exists"),
                            ));
                        }
                        Ok((false, _)) => {
                            let set = nft_set_name_for_jail(jail);
                            findings.push(
                                Finding::new(
                                    "firewall.nft.set-missing",
                                    Severity::Warning,
                                    format!("nft set for jail '{jail}' not found"),
                                )
                                .detail(format!(
                                    "The nft set \"{set}\" in table \
                                     \"{NFT_TABLE_FAMILY} {NFT_TABLE}\" does not exist. It is \
                                     created when a jail with a nftables action \
                                     starts.",
                                ))
                                .fix(format!(
                                    "Start (or restart) jail '{jail}' so Fail2Ban \
                                     creates the nft set, or verify that the \
                                     correct action is configured.",
                                )),
                            );
                        }
                        Err(e) => {
                            let set = nft_set_name_for_jail(jail);
                            findings.push(
                                Finding::new(
                                    "firewall.nft.set-check-error",
                                    Severity::Error,
                                    format!("Failed to check nft set for jail '{jail}'"),
                                )
                                .detail(format!(
                                    "Running `nft list set {NFT_TABLE_FAMILY} {NFT_TABLE} {set}` failed: {e}",
                                )),
                            );
                        }
                    }
                }
            }
            Ok(false) => {
                findings.push(
                    Finding::new(
                        "firewall.nft.missing",
                        Severity::Critical,
                        "nft binary not available",
                    )
                    .detail(
                        "A nftables action is configured but the `nft` binary \
                         could not be executed. Bans will not be enforced at \
                         the firewall level.",
                    )
                    .fix("Install nftables: apt install nftables (Debian/Ubuntu) or dnf install nftables (Fedora)."),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "firewall.nft.check-error",
                        Severity::Error,
                        "Failed to check nft availability",
                    )
                    .detail(format!("Running `nft --version` failed: {e}")),
                );
            }
        }
    }

    /// Run iptables-specific diagnostic probes and append findings, one chain
    /// check per jail (`f2b-<jail>`).
    #[allow(
        clippy::too_many_lines,
        reason = "sequential probe chain, splitting obscures flow"
    )]
    fn diagnose_iptables(&self, jails: &[String], findings: &mut Vec<Finding>) {
        match self.check_iptables_available() {
            Ok(true) => {
                for jail in jails {
                    let chain = iptables_chain_name_for_jail(jail);
                    match self.check_iptables_chain(&chain) {
                        Ok(true) => {
                            findings.push(Finding::new(
                                "firewall.iptables.chain-present",
                                Severity::Ok,
                                format!("iptables chain '{chain}' exists"),
                            ));
                        }
                        Ok(false) => {
                            findings.push(
                                Finding::new(
                                    "firewall.iptables.chain-missing",
                                    Severity::Warning,
                                    format!("iptables chain '{chain}' not found"),
                                )
                                .detail(format!(
                                    "The iptables chain \"{chain}\" does not \
                                     exist. It is created when a jail with an \
                                     iptables action starts.",
                                ))
                                .fix(format!(
                                    "Start (or restart) jail '{jail}' so Fail2Ban \
                                     creates the chain, or verify that the correct \
                                     action is configured.",
                                )),
                            );
                        }
                        Err(e) => {
                            findings.push(
                                Finding::new(
                                    "firewall.iptables.chain-check-error",
                                    Severity::Error,
                                    format!("Failed to check iptables chain '{chain}'"),
                                )
                                .detail(format!("Running `iptables -n -L {chain}` failed: {e}")),
                            );
                        }
                    }
                }
            }
            Ok(false) => {
                findings.push(
                    Finding::new(
                        "firewall.iptables.missing",
                        Severity::Critical,
                        "iptables binary not available",
                    )
                    .detail(
                        "An iptables action is configured but the `iptables` \
                         binary could not be executed. Bans will not be \
                         enforced at the firewall level.",
                    )
                    .fix("Install iptables: apt install iptables (Debian/Ubuntu) or dnf install iptables (Fedora)."),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "firewall.iptables.check-error",
                        Severity::Error,
                        "Failed to check iptables availability",
                    )
                    .detail(format!("Running `iptables --version` failed: {e}")),
                );
            }
        }

        match self.check_ip6tables_available() {
            Ok(true) => {
                findings.push(Finding::new(
                    "firewall.ip6tables.available",
                    Severity::Ok,
                    "ip6tables binary available (IPv6 ban support)",
                ));
            }
            Ok(false) => {
                findings.push(
                    Finding::new(
                        "firewall.ip6tables.missing",
                        Severity::Warning,
                        "ip6tables binary not available",
                    )
                    .detail(
                        "An iptables action is configured but `ip6tables` is \
                         not available. IPv6 addresses will not be banned at \
                         the firewall level.",
                    )
                    .fix("Install ip6tables: apt install iptables (Debian/Ubuntu) or dnf install iptables (Fedora)."),
                );
            }
            Err(e) => {
                findings.push(
                    Finding::new(
                        "firewall.ip6tables.check-error",
                        Severity::Error,
                        "Failed to check ip6tables availability",
                    )
                    .detail(format!("Running `ip6tables --version` failed: {e}")),
                );
            }
        }
    }

    /// Parse the full nftables ruleset from JSON output into structured types.
    ///
    /// Runs `nft -j list ruleset` and deserialises the result into a typed
    /// representation that can be inspected programmatically -- for example to
    /// verify that Fail2Ban's ban sets and rules are present and correctly
    /// ordered.
    ///
    /// # Feature
    ///
    /// Only available when the `firewall-nft` feature is enabled.
    ///
    /// # Returns
    ///
    /// A parsed nftables ruleset on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the `nft` command fails or the JSON output cannot
    /// be deserialised.
    #[cfg(feature = "firewall-nft")]
    pub fn inspect_nft_ruleset_json(&self) -> Result<serde_json::Value> {
        Err(Error::CommandFailed(
            "inspect_nft_ruleset_json not yet implemented: nft/iptables CLI integration pending"
                .into(),
        ))
    }

    /// Parse iptables rules into a structured representation.
    ///
    /// Reads the output of `iptables-save` (or the equivalent via the runner)
    /// and parses each rule into a typed structure covering the table, chain,
    /// match criteria, and target (ACCEPT, DROP, REJECT, jump, etc.).
    ///
    /// # Feature
    ///
    /// Only available when the `firewall-iptables` feature is enabled.
    ///
    /// # Returns
    ///
    /// A collection of parsed iptables rules on success.
    ///
    /// # Errors
    ///
    /// Returns an error if the `iptables-save` command fails or the output
    /// cannot be parsed.
    #[cfg(feature = "firewall-iptables")]
    pub fn inspect_iptables_rules(&self) -> Result<Vec<serde_json::Value>> {
        Err(Error::CommandFailed(
            "inspect_iptables_rules not yet implemented: nft/iptables CLI integration pending"
                .into(),
        ))
    }
}

#[cfg(test)]
#[path = "firewall.test.rs"]
mod tests;
