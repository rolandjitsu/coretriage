//! `coretriage`: the command-line front-end. Triages Linux ELF core dumps - a file is
//! triaged on its own, a directory is triaged in batch and bucketed - and prints the result
//! as text or JSON.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use coretriage_core::{TriageOptions, triage, triage_batch};
use tracing_subscriber::EnvFilter;

/// Triage Linux ELF core dumps: unwind, symbolicate, and bucket crashes and hangs.
#[derive(Debug, Parser)]
#[command(name = "coretriage", version, about)]
struct Cli {
    /// Core files to triage, or directories to triage in batch. At least one is required.
    #[arg(required = true, value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// The crashing executable, when it cannot be located from the core itself.
    #[arg(long, value_name = "FILE")]
    exe: Option<PathBuf>,
    /// Extra root to resolve recorded module paths against; repeatable.
    #[arg(long = "sysroot", value_name = "DIR")]
    sysroot: Vec<PathBuf>,
    /// Maximum number of frames to keep per thread; 0 keeps all.
    #[arg(long, default_value_t = 16)]
    top: usize,
    /// Emit JSON instead of text.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts = TriageOptions {
        exe: cli.exe,
        sysroot: cli.sysroot,
        top: cli.top,
    };

    let mut failed = false;
    for path in &cli.paths {
        let outcome = if path.is_dir() {
            run_batch(path, &opts, cli.json)
        } else {
            run_one(path, &opts, cli.json)
        };
        if let Err(err) = outcome {
            eprintln!("coretriage: {}: {err:#}", path.display());
            failed = true;
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run_one(path: &Path, opts: &TriageOptions, json: bool) -> Result<()> {
    tracing::info!(core = %path.display(), "triaging core");
    let report = triage(path, opts)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{report:#?}");
    }
    Ok(())
}

fn run_batch(dir: &Path, opts: &TriageOptions, json: bool) -> Result<()> {
    tracing::info!(dir = %dir.display(), "triaging directory");
    let buckets = triage_batch(dir, opts)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&buckets)?);
    } else {
        for bucket in &buckets {
            println!("{bucket:#?}");
        }
    }
    Ok(())
}
