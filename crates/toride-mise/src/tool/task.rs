//! Task management via `mise tasks` and `mise run`.
//!
//! Exposes [`TaskInfo`] and [`TaskRunRequest`] for describing tasks and
//! their execution parameters, and adds [`Mise::tasks_list`],
//! [`Mise::task_info`], [`Mise::task_edit_path`],
//! [`Mise::task_deps`], [`Mise::task_run`], and
//! [`Mise::tasks_validate`] methods on the client.

use camino::Utf8PathBuf;
use serde::Deserialize;

use crate::client::Mise;
use crate::error::MiseResult;

// ---------------------------------------------------------------------------
// JSON response types
// ---------------------------------------------------------------------------

/// A single task entry as returned by `mise tasks ls --json`.
#[derive(Debug, Clone, Deserialize)]
pub struct TaskInfo {
    /// The task name (e.g. `"build"`).
    pub name: String,
    /// A short human-readable description of the task.
    #[serde(default)]
    pub description: Option<String>,
    /// The file source where the task is defined.
    #[serde(default)]
    pub source: Option<String>,
    /// Names of tasks this task depends on.
    #[serde(default)]
    pub depends: Vec<String>,
}

/// Parameters for executing a task via [`Mise::task_run`].
#[derive(Debug, Clone)]
pub struct TaskRunRequest {
    /// The task name to execute.
    pub task: String,
    /// Positional arguments forwarded to the task.
    pub args: Vec<String>,
    /// Working directory override for the task invocation.
    pub cwd: Option<Utf8PathBuf>,
    /// Tool specifications to make available during execution
    /// (e.g. `["node@22", "python@3.12"]`).
    pub tools: Vec<String>,
}

// ---------------------------------------------------------------------------
// Mise methods
// ---------------------------------------------------------------------------

impl Mise {
    /// List all defined tasks.
    ///
    /// Invokes `mise tasks ls --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn tasks_list(&self) -> MiseResult<Vec<TaskInfo>> {
        self.run_json(["tasks", "ls", "--json"]).await
    }

    /// Get detailed information about a single task.
    ///
    /// Invokes `mise tasks info <name> --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn task_info(&self, name: &str) -> MiseResult<TaskInfo> {
        self.run_json(["tasks", "info", name, "--json"]).await
    }

    /// Return the filesystem path where a task is defined.
    ///
    /// Invokes `mise tasks edit <name> --path`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn task_edit_path(&self, name: &str) -> MiseResult<Utf8PathBuf> {
        let output = self.run_checked(["tasks", "edit", name, "--path"]).await?;
        Ok(Utf8PathBuf::from(output.stdout_trimmed().to_owned()))
    }

    /// Resolve the dependency graph for one or more tasks.
    ///
    /// Invokes `mise tasks deps [tasks…]`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn task_deps(&self, tasks: &[&str]) -> MiseResult<Vec<String>> {
        let mut args: Vec<&str> = vec!["tasks", "deps"];
        args.extend_from_slice(tasks);
        let output = self.run_checked(args).await?;
        let deps = output.stdout_trimmed().lines().map(str::to_owned).collect();
        Ok(deps)
    }

    /// Execute a task with the given parameters.
    ///
    /// When `req.tools` is non-empty the method invokes `mise run --tool
    /// <spec>… <task> [args…]`; otherwise it invokes `mise run <task>
    /// [args…]`.
    ///
    /// If `req.cwd` is set it is passed as `--cwd <path>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn task_run(&self, req: &TaskRunRequest) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["run".into()];

        // Tool specifications.
        for spec in &req.tools {
            args.push("--tool".into());
            args.push(spec.clone());
        }

        // Working directory override.
        if let Some(ref cwd) = req.cwd {
            args.push("--cwd".into());
            args.push(cwd.to_string());
        }

        // Task name and positional arguments.
        args.push(req.task.clone());
        args.extend(req.args.iter().cloned());

        self.run_checked(args).await?;
        Ok(())
    }

    /// Validate all task definitions and return the report.
    ///
    /// Invokes `mise tasks validate --json`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    /// Returns [`MiseError::JsonParse`] if the output cannot be deserialised.
    pub async fn tasks_validate(&self) -> MiseResult<String> {
        let output = self.run_checked(["tasks", "validate", "--json"]).await?;
        Ok(output.stdout_trimmed().to_owned())
    }

    /// Add a new task definition.
    ///
    /// Invokes `mise tasks add <name> -- <run_cmd…>`.
    ///
    /// # Errors
    ///
    /// Returns [`MiseError::CommandFailed`] if the command exits non-zero.
    pub async fn task_add(&self, name: &str, run_cmd: Vec<String>) -> MiseResult<()> {
        let mut args: Vec<String> = vec!["tasks".into(), "add".into(), name.into(), "--".into()];
        args.extend(run_cmd);
        self.run_checked(args).await?;
        Ok(())
    }
}
