//! Rendering functions for backup configuration as human-readable text.
//!
//! Provides renderers that produce CLI-friendly output for retention policies,
//! schedule configurations, and backup specs.

use crate::spec::{BackupSpec, RetentionPolicy, Schedule};

// ---------------------------------------------------------------------------
// Retention policy renderer
// ---------------------------------------------------------------------------

/// Render a [`RetentionPolicy`] as a human-readable summary.
///
/// Produces a multi-line string describing each keep-* count, e.g.:
///
/// ```text
/// Retention Policy:
///   Keep daily:   7
///   Keep weekly:  4
///   Keep monthly: 6
/// ```
pub fn render_retention_policy(policy: &RetentionPolicy) -> String {
    let mut lines = vec!["Retention Policy:".to_string()];

    if let Some(h) = policy.keep_hourly {
        lines.push(format!("  Keep hourly:  {h}"));
    }
    if let Some(d) = policy.keep_daily {
        lines.push(format!("  Keep daily:   {d}"));
    }
    if let Some(w) = policy.keep_weekly {
        lines.push(format!("  Keep weekly:  {w}"));
    }
    if let Some(m) = policy.keep_monthly {
        lines.push(format!("  Keep monthly: {m}"));
    }
    if let Some(y) = policy.keep_yearly {
        lines.push(format!("  Keep yearly:  {y}"));
    }

    if lines.len() == 1 {
        lines.push("  (no retention rules configured)".into());
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Schedule config renderer
// ---------------------------------------------------------------------------

/// Render a [`Schedule`] as a human-readable description.
///
/// Produces a single-line description, e.g.:
///
/// ```text
/// Schedule: 0 2 * * * (daily at 02:00)
/// ```
pub fn render_schedule_config(schedule: &Schedule) -> String {
    let desc = schedule
        .description
        .as_deref()
        .unwrap_or_else(|| describe_cron_fallback(&schedule.cron));
    format!("Schedule: {} ({})", schedule.cron, desc)
}

/// Best-effort human-readable description of a cron expression.
///
/// Only handles the most common patterns. Falls back to "custom schedule"
/// for expressions that are not recognised.
fn describe_cron_fallback(cron: &str) -> &'static str {
    match cron {
        "0 2 * * *" => "daily at 02:00",
        "0 3 * * *" => "daily at 03:00",
        "0 4 * * *" => "daily at 04:00",
        "0 * * * *" => "hourly",
        "0 0 * * 0" => "weekly on Sunday",
        "0 0 1 * *" => "monthly on the 1st",
        _ => "custom schedule",
    }
}

// ---------------------------------------------------------------------------
// Backup spec renderer
// ---------------------------------------------------------------------------

/// Render a full [`BackupSpec`] as a human-readable summary.
///
/// Produces a multi-line description suitable for `--dry-run` output or
/// logging.
pub fn render_backup_spec(spec: &BackupSpec) -> String {
    let mut lines = vec![format!("Backup: {}", spec.name)];

    lines.push(format!("  Backend:    {}", spec.backend));
    lines.push(format!("  Repository: {}", spec.repository.display()));
    lines.push(format!(
        "  Sources:    {}",
        spec.sources
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines.push(format!("  Encryption: {}", spec.encryption));
    lines.push(render_schedule_config(&spec.schedule));
    lines.push(render_retention_policy(&spec.retention));

    if !spec.exclude_patterns.is_empty() {
        lines.push(format!(
            "  Excludes:   {}",
            spec.exclude_patterns.join(", ")
        ));
    }

    if !spec.tags.is_empty() {
        lines.push(format!("  Tags:       {}", spec.tags.join(", ")));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
