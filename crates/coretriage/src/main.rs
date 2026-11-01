//! `coretriage`: the command-line front-end. Triages Linux ELF core dumps - a file is triaged
//! on its own, a directory is triaged in batch and bucketed - and renders the result through the
//! selected output emitter.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use coretriage_core::{Emitter, JsonEmitter, TextEmitter, TriageOptions, triage, triage_batch};
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
    /// Debug store searched by GNU build-id for stripped binaries and separate debuginfo;
    /// repeatable. Accepts the elfutils `.build-id/<ab>/<rest>` layout or the debuginfod
    /// `buildid/<id>/{executable,debuginfo}` layout. Defaults to /usr/lib/debug.
    #[arg(long = "debug-dir", value_name = "DIR")]
    debug_dir: Vec<PathBuf>,
    /// Fetch missing binaries and debuginfo by build-id from a debuginfod server
    /// ($DEBUGINFOD_URLS). Requires a build with --features debuginfod.
    #[arg(long)]
    debuginfod: bool,
    /// Maximum number of frames to keep per thread; 0 keeps all.
    #[arg(long, default_value_t = 16)]
    top: usize,
    /// Output format.
    #[arg(long, default_value = "text")]
    format: OutputFormat,
}

/// The output formats the CLI can render.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable text.
    Text,
    /// JSON for machine consumption.
    Json,
}

impl OutputFormat {
    /// The emitter that renders this format.
    fn emitter(self) -> Box<dyn Emitter> {
        match self {
            OutputFormat::Text => Box::new(TextEmitter),
            OutputFormat::Json => Box::new(JsonEmitter { pretty: true }),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Logs go to stderr so stdout carries only the report (clean JSON for piping).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // --debuginfod is always accepted so its help is visible, but it only works in a build with
    // the feature; otherwise fail loudly rather than silently ignoring it.
    #[cfg(not(feature = "debuginfod"))]
    if cli.debuginfod {
        eprintln!(
            "coretriage: built without debuginfod support; rebuild with --features debuginfod"
        );
        return ExitCode::FAILURE;
    }

    let opts = TriageOptions {
        exe: cli.exe,
        sysroot: cli.sysroot,
        debug_dirs: cli.debug_dir,
        debuginfod: cli.debuginfod,
        top: cli.top,
    };
    let emitter = cli.format.emitter();

    let mut failed = false;
    for path in &cli.paths {
        let outcome = if path.is_dir() {
            run_batch(path, &opts, emitter.as_ref())
        } else {
            run_one(path, &opts, emitter.as_ref())
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

fn run_one(path: &Path, opts: &TriageOptions, emitter: &dyn Emitter) -> Result<()> {
    tracing::info!(core = %path.display(), "triaging core");
    let report = triage(path, opts)?;
    let mut out = std::io::stdout().lock();
    emitter.emit_report(&report, &mut out)?;
    out.flush()?;
    Ok(())
}

fn run_batch(dir: &Path, opts: &TriageOptions, emitter: &dyn Emitter) -> Result<()> {
    tracing::info!(dir = %dir.display(), "triaging directory");
    let buckets = triage_batch(dir, opts)?;
    let mut out = std::io::stdout().lock();
    emitter.emit_buckets(&buckets, &mut out)?;
    out.flush()?;
    Ok(())
}
