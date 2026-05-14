use toride::executor;
use toride::profiles;
use toride::system;
use toride::tui;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "toride", version, about = "VPS setup tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[arg(long)]
    profile: Option<String>,

    #[arg(long)]
    config: Option<String>,

    #[arg(long)]
    user: Option<String>,

    #[arg(long)]
    ssh_key: Option<String>,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    no_animation: bool,

    #[arg(long)]
    no_color: bool,

    #[arg(long, default_value = "auto")]
    color: String,
}

#[derive(Subcommand)]
enum Commands {
    Plan {
        #[arg(long)]
        profile: Option<String>,

        #[arg(long)]
        config: Option<String>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        export: Option<String>,
    },
    Apply {
        #[arg(long)]
        profile: Option<String>,

        #[arg(long)]
        config: Option<String>,

        #[arg(long)]
        user: Option<String>,

        #[arg(long)]
        ssh_key: Option<String>,

        #[arg(long)]
        remote: Option<String>,
    },
    Refresh {
        #[arg(value_name = "TARGET")]
        target: String,
    },
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    if cli.no_animation {
        unsafe { std::env::set_var("TORIDE_NO_ANIM", "1"); }
    }
    if cli.no_color || cli.color == "never" {
        unsafe { std::env::set_var("NO_COLOR", "1"); }
    }
    if cli.color == "always" {
        unsafe { std::env::set_var("FORCE_COLOR", "1"); }
    }

    match cli.command {
        Some(Commands::Plan { profile, config: config_path, json, export }) => {
            run_plan(profile.as_deref(), config_path.as_deref(), json, export).await
        }
        Some(Commands::Apply { profile, config: config_path, user, ssh_key, remote }) => {
            if let Some(host) = remote {
                run_remote(profile.as_deref(), &host, user.as_deref(), ssh_key.as_deref()).await
            } else {
                run_apply(profile.as_deref(), config_path.as_deref(), user.as_deref(), ssh_key.as_deref()).await
            }
        }
        Some(Commands::Refresh { target }) => {
            run_refresh(&target).await
        }
        None => {
            tui::runtime::run().await
        }
    }
}

async fn run_plan(profile: Option<&str>, _config_path: Option<&str>, json: bool, export_path: Option<String>) -> color_eyre::Result<()> {
    let profile = match profile {
        Some("basic") => tui::model::Profile::Basic,
        Some("sandbox") => tui::model::Profile::Sandbox,
        Some("custom") | None => tui::model::Profile::Custom,
        _ => tui::model::Profile::Custom,
    };

    let defaults = profiles::profile_defaults(profile);
    let plan = executor::plan::generate_plan(&defaults, "", "").await?;

    if json {
        let output = serde_json::to_string_pretty(&plan.actions.iter().map(|a| {
            serde_json::json!({
                "module": a.module_id.label(),
                "action": a.label,
                "status": format!("{:?}", a.status),
            })
        }).collect::<Vec<_>>())?;
        println!("{}", output);
    } else {
        let report = executor::dry_run::dry_run_report(&plan);
        println!("{}", report);
    }

    if let Some(path) = export_path {
        let export_data = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "profile": format!("{:?}", profile),
            "generated_at": chrono_like_timestamp(),
            "actions": plan.actions.iter().map(|a| {
                serde_json::json!({
                    "module": a.module_id.label(),
                    "action": a.label,
                    "status": format!("{:?}", a.status),
                })
            }).collect::<Vec<_>>(),
        });
        let content = serde_json::to_string_pretty(&export_data)?;
        std::fs::write(&path, content.as_bytes())?;
        eprintln!("Plan exported to {}", path);
    }

    Ok(())
}

async fn run_apply(profile: Option<&str>, _config_path: Option<&str>, user: Option<&str>, ssh_key: Option<&str>) -> color_eyre::Result<()> {
    let profile = match profile {
        Some("basic") => tui::model::Profile::Basic,
        Some("sandbox") => tui::model::Profile::Sandbox,
        Some("custom") | None => tui::model::Profile::Custom,
        _ => tui::model::Profile::Custom,
    };

    if !system::users::is_root() {
        eprintln!("Apply requires root. Run: sudo toride apply --profile {}", match profile {
            tui::model::Profile::Basic => "basic",
            tui::model::Profile::Sandbox => "sandbox",
            tui::model::Profile::Custom => "custom",
        });
        std::process::exit(1);
    }

    let target_user = user.unwrap_or("deploy").to_string();
    let ssh_public_key = ssh_key.unwrap_or("").to_string();

    let defaults = profiles::profile_defaults(profile);
    let plan = executor::plan::generate_plan(&defaults, &target_user, &ssh_public_key).await?;

    let ctx = toride::modules::Context {
        is_dry_run: false,
        is_test: std::env::var("TORIDE_E2E").is_ok(),
        target_user: target_user.clone(),
        ssh_public_key: ssh_public_key.clone(),
    };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let plan_clone = plan.clone();

    let handle = tokio::spawn(async move {
        executor::execute_plan(&plan_clone, tx, cancel_clone, ctx).await
    });

    while let Some(event) = rx.recv().await {
        match event {
            tui::model::ProgressEvent::StepStart { label, .. } => {
                println!("[RUNNING] {}", label);
            }
            tui::model::ProgressEvent::StepDone { .. } => {
                println!("[DONE]");
            }
            tui::model::ProgressEvent::StepFail { error, .. } => {
                println!("[FAILED] {}", error);
            }
            tui::model::ProgressEvent::StepLog { line, .. } => {
                println!("  {}", line);
            }
        }
    }

    match handle.await? {
        Ok(outcome) => match outcome {
            tui::model::Outcome::Success => println!("\nSetup complete."),
            tui::model::Outcome::PartialSuccess { failed } => {
                println!("\nSetup completed with failures: {:?}", failed);
            }
            tui::model::Outcome::Failed { error } => println!("\nSetup failed: {}", error),
            tui::model::Outcome::Cancelled => println!("\nSetup cancelled."),
        },
        Err(e) => return Err(e),
    }

    Ok(())
}

async fn run_remote(profile: Option<&str>, host: &str, user: Option<&str>, ssh_key: Option<&str>) -> color_eyre::Result<()> {
    let profile_str = profile.unwrap_or("basic");
    let mut cmd = format!("toride apply --profile {}", profile_str);
    if let Some(u) = user {
        cmd.push_str(&format!(" --user {}", u));
    }
    if let Some(k) = ssh_key {
        cmd.push_str(&format!(" --ssh-key {}", k));
    }

    println!("Connecting to {}...", host);
    let mut child = tokio::process::Command::new("ssh")
        .args(["-t", host, &cmd])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    let status = child.wait().await?;
    if status.success() {
        println!("\nRemote setup complete.");
    } else {
        eprintln!("\nRemote setup failed with exit code: {:?}", status.code());
    }

    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("toride=info"));

    // Try file logging in addition to stderr
    let dir = toride::executor::logs::log_dir();
    if std::fs::create_dir_all(&dir).is_ok() {
        let file_appender = tracing_appender::rolling::never(&dir, "setup.log");
        let (file_nb, guard) = tracing_appender::non_blocking(file_appender);
        // Leak guard to keep file writer alive for program lifetime
        std::mem::forget(guard);

        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(file_nb)
            .with_ansi(false);

        tracing_subscriber::registry()
            .with(filter)
            .with(stderr_layer)
            .with(file_layer)
            .init();
        return;
    }

    // Fallback: stderr only
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn chrono_like_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}

async fn run_refresh(target: &str) -> color_eyre::Result<()> {
    match target {
        "cloudflare-ips" => {
            println!("Fetching Cloudflare IP ranges...");

            let ipv4 = match reqwest::get("https://www.cloudflare.com/ips-v4").await {
                Ok(resp) => resp.text().await.unwrap_or_default(),
                Err(e) => return Err(color_eyre::eyre::eyre!("Failed to fetch IPv4 ranges: {}", e)),
            };
            let ipv6 = match reqwest::get("https://www.cloudflare.com/ips-v6").await {
                Ok(resp) => resp.text().await.unwrap_or_default(),
                Err(e) => return Err(color_eyre::eyre::eyre!("Failed to fetch IPv6 ranges: {}", e)),
            };

            let ranges: Vec<&str> = ipv4.lines().chain(ipv6.lines())
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();

            if ranges.is_empty() {
                eprintln!("No IP ranges fetched. Keeping existing rules.");
                return Ok(());
            }

            println!("Fetched {} IP ranges.", ranges.len());

            let cache_dir = std::path::Path::new("/var/lib/toride");
            if let Err(e) = std::fs::create_dir_all(cache_dir) {
                eprintln!("Warning: could not create cache dir: {}", e);
            }

            let cache_path = cache_dir.join("cloudflare-ips.txt");
            let content = format!(
                "# Updated {}\n# IPv4\n{}\n# IPv6\n{}\n",
                chrono_like_timestamp(),
                ipv4.trim(),
                ipv6.trim(),
            );
            std::fs::write(&cache_path, &content)?;
            println!("Cached to {}", cache_path.display());

            // Update UFW rules if UFW is active
            let ufw_status = std::process::Command::new("ufw")
                .arg("status")
                .output()
                .ok();
            let is_active = ufw_status
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.contains("active"))
                .unwrap_or(false);

            if is_active {
                println!("Updating UFW rules...");
                // Remove old Cloudflare rules (tagged with comment)
                let _ = std::process::Command::new("ufw")
                    .args(["delete", "allow", "from", "any", "to", "any", "port", "80", "comment", "toride-cloudflare"])
                    .output();
                let _ = std::process::Command::new("ufw")
                    .args(["delete", "allow", "from", "any", "to", "any", "port", "443", "comment", "toride-cloudflare"])
                    .output();

                for range in &ranges {
                    let _ = std::process::Command::new("ufw")
                        .args(["allow", "from", range, "to", "any", "port", "80", "comment", "toride-cloudflare"])
                        .output();
                    let _ = std::process::Command::new("ufw")
                        .args(["allow", "from", range, "to", "any", "port", "443", "comment", "toride-cloudflare"])
                        .output();
                }
                println!("UFW rules updated.");
            }

            println!("Cloudflare IP refresh complete.");
            Ok(())
        }
        _ => {
            eprintln!("Unknown refresh target: {}. Supported: cloudflare-ips", target);
            std::process::exit(1);
        }
    }
}
