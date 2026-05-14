use toride::config;
use toride::executor;
use toride::modules;
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
        Some(Commands::Plan { profile, config: config_path, json }) => {
            run_plan(profile.as_deref(), config_path.as_deref(), json).await
        }
        Some(Commands::Apply { profile, config: config_path, user, ssh_key }) => {
            run_apply(profile.as_deref(), config_path.as_deref(), user.as_deref(), ssh_key.as_deref()).await
        }
        None => {
            tui::runtime::run().await
        }
    }
}

async fn run_plan(profile: Option<&str>, _config_path: Option<&str>, json: bool) -> color_eyre::Result<()> {
    let profile = match profile {
        Some("basic") => tui::model::Profile::Basic,
        Some("custom") | None => tui::model::Profile::Custom,
        _ => tui::model::Profile::Custom,
    };

    let defaults = profiles::profile_defaults(profile);
    let plan = executor::plan::generate_plan(&defaults).await?;

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

    Ok(())
}

async fn run_apply(profile: Option<&str>, config_path: Option<&str>, user: Option<&str>, ssh_key: Option<&str>) -> color_eyre::Result<()> {
    let profile = match profile {
        Some("basic") => tui::model::Profile::Basic,
        Some("custom") | None => tui::model::Profile::Custom,
        _ => tui::model::Profile::Custom,
    };

    if !system::users::is_root() {
        eprintln!("Apply requires root. Run: sudo toride apply --profile {}", match profile {
            tui::model::Profile::Basic => "basic",
            tui::model::Profile::Custom => "custom",
        });
        std::process::exit(1);
    }

    let defaults = profiles::profile_defaults(profile);
    let plan = executor::plan::generate_plan(&defaults).await?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let cancel_clone = cancel.clone();
    let plan_clone = plan.clone();

    let handle = tokio::spawn(async move {
        executor::execute_plan(&plan_clone, tx, cancel_clone).await
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

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("toride=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
