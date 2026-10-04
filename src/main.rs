use std::collections::BTreeMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use tokio::net::lookup_host;
use tokio::sync::mpsc;

use oncep::output::{self, Emitter, Format};
use oncep::probe::TcpProbe;
use oncep::progress::{self, LiveStats, ProgressMode};
use oncep::scan::{self, ResolvedName, ScanConfig, Target};
use oncep::targets::{self, shuffle};

macro_rules! banner {
    () => {
        concat!(
            "┌─┐ ┌┐┌ ┌─┐ ┌─┐ ┌─┐\n",
            "│ │ │││ │   ├─┤ ├─┘\n",
            "└─┘ ┘└┘ └─┘ └─┘ ┴\n",
            "v",
            env!("CARGO_PKG_VERSION"),
            " · mexsic.io"
        )
    };
}

#[derive(Parser)]
#[command(
    name = "oncep",
    version,
    about = "TCP port scanner with per-port confidence and an ETA",
    before_help = banner!()
)]
struct Cli {
    /// IP, hostname, or CIDR. A large CIDR has to be written out.
    targets: Vec<String>,

    /// Ports: 22 | 80,443 | 1-1024 | - for 1-65535.
    #[arg(short = 'p', long = "ports", default_value = "1-1024", allow_hyphen_values = true)]
    ports: String,

    /// Maximum attempts per port. A silence stops at --min-confidence once the host has answered.
    #[arg(long, default_value_t = 3)]
    attempts: u32,

    /// Spend the whole budget even after a reply or enough confidence.
    #[arg(long)]
    insist: bool,

    /// Below this, the published state is uncertain.
    #[arg(long, default_value_t = 0.95)]
    min_confidence: f64,

    /// Timeout ceiling, in milliseconds. The floor is 100.
    #[arg(long, default_value_t = 2000)]
    timeout: u64,

    /// Simultaneous attempts. The default comes from the open-file limit.
    #[arg(short = 'c', long)]
    concurrency: Option<usize>,

    /// Attempts per second.
    #[arg(long, default_value_t = 2000)]
    rate: u32,

    /// Shuffle seed. It is printed in the JSON summary.
    #[arg(long)]
    seed: Option<u64>,

    /// Do not shuffle the ports.
    #[arg(long)]
    ordered: bool,

    /// File with one target per line.
    #[arg(short = 'f', long = "targets")]
    targets_file: Option<PathBuf>,

    /// Ports to skip. Same syntax as --ports.
    #[arg(long)]
    exclude: Option<String>,

    /// Keep going even if the 24-port sample gets no reply.
    #[arg(long)]
    force: bool,

    /// No banner and no progress. The text summary goes to the result output.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// auto, always, or never.
    #[arg(long, default_value = "auto")]
    progress: String,

    /// text, txt, or json.
    #[arg(short = 'F', long = "format", default_value = "text")]
    format: String,

    /// For text: open or all. txt and json always write every port.
    #[arg(long, default_value = "open")]
    show: String,

    /// Result file. Progress stays on stderr.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("oncep: {err}");
            ExitCode::from(err.code)
        }
    }
}

struct Fail {
    code: u8,
    message: String,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn fail(code: u8, message: impl Into<String>) -> Fail {
    Fail {
        code,
        message: message.into(),
    }
}

async fn run(cli: Cli) -> Result<(), Fail> {
    if !cli.quiet {
        eprintln!("{}\n", banner!());
    }
    if cli.attempts == 0 {
        return Err(fail(2, "--attempts must be at least 1"));
    }
    if !(cli.min_confidence > 0.0 && cli.min_confidence <= 1.0) {
        return Err(fail(2, "--min-confidence is between 0 and 1, excluding 0"));
    }
    if cli.timeout < 100 {
        return Err(fail(2, "--timeout is the ceiling and the minimum is 100 ms"));
    }
    if cli.rate == 0 {
        return Err(fail(2, "--rate must be at least 1"));
    }
    if let Some(0) = cli.concurrency {
        return Err(fail(2, "--concurrency must be at least 1"));
    }

    let format = output::parse_format(&cli.format).map_err(|m| fail(2, m))?;
    let show = output::parse_show(&cli.show).map_err(|m| fail(2, m))?;
    let mut progress = progress::parse_mode(&cli.progress).map_err(|m| fail(2, m))?;
    if cli.quiet && progress == ProgressMode::Auto {
        progress = ProgressMode::Never;
    }

    let mut ports = targets::parse_ports(&cli.ports).map_err(|m| fail(2, m))?;
    if let Some(exclude) = &cli.exclude {
        let exclude = targets::parse_ports(exclude).map_err(|m| fail(2, m))?;
        ports = targets::subtract_ports(ports, &exclude);
    }
    if ports.is_empty() {
        return Err(fail(2, "no ports left after --exclude"));
    }

    let mut raw_targets = cli.targets;
    if let Some(path) = &cli.targets_file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| fail(1, format!("could not read {}: {e}", path.display())))?;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            raw_targets.push(line.to_string());
        }
    }
    if raw_targets.is_empty() {
        return Err(fail(2, "give at least one target"));
    }

    let seed = cli.seed.unwrap_or_else(fresh_seed);
    let mut by_ip: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    let mut resolved = Vec::new();
    for raw in &raw_targets {
        let ips = resolve(raw).await?;
        announce(raw, &ips);
        resolved.push(ResolvedName {
            query: raw.clone(),
            ips: ips.clone(),
        });
        for ip in ips {
            let entry = by_ip.entry(ip).or_insert_with(|| ports.clone());
            if entry != &ports {
                let mut merged = entry.clone();
                for port in &ports {
                    if !merged.contains(port) {
                        merged.push(*port);
                    }
                }
                merged.sort_unstable();
                *entry = merged;
            }
        }
    }

    let targets: Vec<Target> = by_ip
        .into_iter()
        .map(|(ip, mut ports)| {
            if !cli.ordered {
                shuffle(&mut ports, seed ^ ip_mix(&ip));
            }
            Target { ip, ports }
        })
        .collect();

    let total: u64 = targets.iter().map(|t| t.ports.len() as u64).sum();
    let cfg = ScanConfig {
        attempts: cli.attempts,
        insist: cli.insist,
        min_confidence: cli.min_confidence,
        timeout_max: Duration::from_millis(cli.timeout),
        concurrency: cli.concurrency.unwrap_or_else(targets::system_concurrency).max(1),
        rate: cli.rate,
        seed,
        ordered: cli.ordered,
        force: cli.force,
    };

    let summary_on_stderr = cli.output.is_none() && format == Format::Text && !cli.quiet;
    let mut emitter = if let Some(path) = &cli.output {
        Emitter::file(path, format, show)
            .map_err(|e| fail(1, format!("could not create {}: {e}", path.display())))?
    } else {
        Emitter::stdout(format, show, summary_on_stderr)
    };

    let (tx, mut rx) = mpsc::unbounded_channel();
    let stats = Arc::new(LiveStats::new(total));
    let progress_task = progress::spawn(Arc::clone(&stats), progress);
    let started = std::time::Instant::now();
    let scan_task = {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move { scan::scan(targets, cfg, TcpProbe, tx, stats).await })
    };

    let mut write_error = None;
    while let Some(event) = rx.recv().await {
        if let Err(e) = emitter.event(&event) {
            write_error = Some(e);
            break;
        }
    }
    let mut summary = scan_task
        .await
        .map_err(|_| fail(1, "the scan was interrupted"))?;
    summary.resolved = resolved;
    stats.stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Some(task) = progress_task {
        let _ = task.await;
    }
    if let Some(e) = write_error {
        return Err(fail(1, format!("could not write the output: {e}")));
    }
    emitter
        .summary(&summary, started.elapsed())
        .map_err(|e| fail(1, format!("could not write the summary: {e}")))?;
    let _ = io::stdout().flush();
    Ok(())
}

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

fn announce(query: &str, ips: &[IpAddr]) {
    if let Ok(ip) = query.parse::<IpAddr>() {
        if ips.len() == 1 && ips[0] == ip {
            return;
        }
    }
    let list = ips
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!("{query} → {list}");
}

async fn resolve(raw: &str) -> Result<Vec<IpAddr>, Fail> {
    if raw.contains('/') || raw.parse::<IpAddr>().is_ok() {
        return targets::expand_ip_spec(raw).map_err(|m| fail(2, m));
    }
    let mut ips = Vec::new();
    let looked = tokio::time::timeout(RESOLVE_TIMEOUT, lookup_host((raw, 0)))
        .await
        .map_err(|_| fail(1, format!("the resolver did not answer for {raw} within 5s")))?;
    let addrs = looked.map_err(|e| fail(1, format!("could not resolve {raw}: {e}")))?;
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        return Err(fail(1, format!("could not resolve {raw}")));
    }
    Ok(ips)
}

fn fresh_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37);
    let mut mix = targets::SplitMix64::new(nanos);
    mix.next()
}

fn ip_mix(ip: &IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => u32::from(*v4) as u64,
        IpAddr::V6(v6) => {
            let n = u128::from(*v6);
            (n as u64) ^ ((n >> 64) as u64)
        }
    }
}
