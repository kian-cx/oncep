use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;

pub struct LiveStats {
    pub total: AtomicU64,
    pub settled: AtomicU64,
    pub open: AtomicU64,
    pub eta_ms: AtomicU64,
    pub eta_lo_ms: AtomicU64,
    pub eta_hi_ms: AtomicU64,
    /// Frozen after 32 ports, when the ETA drops the tilde.
    pub eta_frozen: AtomicBool,
    pub approx: AtomicBool,
    pub stop: AtomicBool,
    pub started: Instant,
}

impl LiveStats {
    pub fn new(total: u64) -> Self {
        Self {
            total: AtomicU64::new(total),
            settled: AtomicU64::new(0),
            open: AtomicU64::new(0),
            eta_ms: AtomicU64::new(0),
            eta_lo_ms: AtomicU64::new(0),
            eta_hi_ms: AtomicU64::new(0),
            eta_frozen: AtomicBool::new(false),
            approx: AtomicBool::new(true),
            stop: AtomicBool::new(false),
            started: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressMode {
    Auto,
    Always,
    Never,
}

pub fn parse_mode(raw: &str) -> Result<ProgressMode, String> {
    match raw {
        "auto" => Ok(ProgressMode::Auto),
        "always" => Ok(ProgressMode::Always),
        "never" => Ok(ProgressMode::Never),
        _ => Err("progress: use auto, always, or never".into()),
    }
}

pub fn spawn(stats: Arc<LiveStats>, mode: ProgressMode) -> Option<JoinHandle<()>> {
    if mode == ProgressMode::Never {
        return None;
    }
    let tty = io::stderr().is_terminal();
    let redraw = tty && matches!(mode, ProgressMode::Auto | ProgressMode::Always);
    let newline = !tty && matches!(mode, ProgressMode::Auto | ProgressMode::Always);
    if !redraw && !newline {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut last_line = Instant::now() - Duration::from_secs(3);
        let mut drew = false;
        loop {
            if stats.stop.load(Ordering::Relaxed) {
                break;
            }
            if redraw {
                draw(&stats, true);
                drew = true;
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else if last_line.elapsed() >= Duration::from_secs(2) {
                draw(&stats, false);
                last_line = Instant::now();
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        if drew {
            let mut err = io::stderr();
            let _ = writeln!(err);
            let _ = err.flush();
        }
    }))
}

fn draw(stats: &LiveStats, carriage: bool) {
    let total = stats.total.load(Ordering::Relaxed);
    let settled = stats.settled.load(Ordering::Relaxed);
    let open = stats.open.load(Ordering::Relaxed);
    let pct = if total == 0 {
        100
    } else {
        (settled.saturating_mul(100) / total).min(100)
    };
    let elapsed = stats.started.elapsed().as_secs_f64().max(0.001);
    let rate = (settled as f64 / elapsed).round() as u64;
    let eta_ms = stats.eta_ms.load(Ordering::Relaxed);
    let approx = stats.approx.load(Ordering::Relaxed);
    let eta = format_eta(eta_ms as f64 / 1000.0, approx);
    let line = format!("{pct}%  {settled}/{total}  open {open}  {rate} p/s  eta {eta}");
    let mut err = io::stderr();
    if carriage {
        let _ = write!(err, "\r{line}\x1b[K");
    } else {
        let _ = writeln!(err, "{line}");
    }
    let _ = err.flush();
}

pub fn format_eta(secs: f64, approx: bool) -> String {
    let secs = secs.max(0.0).round() as u64;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    let body = format!("{h}:{m:02}:{s:02}");
    if approx {
        format!("~{body}")
    } else {
        body
    }
}

pub fn format_elapsed(d: Duration) -> String {
    let s = d.as_secs_f64();
    if s < 60.0 {
        format!("{s:.1}s")
    } else {
        format_eta(s, false)
    }
}
