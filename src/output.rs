use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use crate::progress::format_elapsed;
use crate::scan::{Event, HostSkip, PortResult, Summary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Txt,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Show {
    Open,
    All,
}

pub fn parse_format(raw: &str) -> Result<Format, String> {
    match raw {
        "text" => Ok(Format::Text),
        "txt" => Ok(Format::Txt),
        "json" => Ok(Format::Json),
        _ => Err("format: use text, txt, or json".into()),
    }
}

pub fn parse_show(raw: &str) -> Result<Show, String> {
    match raw {
        "open" => Ok(Show::Open),
        "all" => Ok(Show::All),
        _ => Err("show: use open or all".into()),
    }
}

pub struct Emitter {
    inner: BufWriter<Box<dyn Write + Send>>,
    format: Format,
    show: Show,
    /// In text mode, the summary goes here when we are not writing a file.
    summary_err: bool,
}

impl Emitter {
    pub fn stdout(format: Format, show: Show, summary_err: bool) -> Self {
        Self {
            inner: BufWriter::new(Box::new(io::stdout())),
            format,
            show,
            summary_err,
        }
    }

    pub fn file(path: &Path, format: Format, show: Show) -> io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self {
            inner: BufWriter::new(Box::new(file)),
            format,
            show,
            summary_err: false,
        })
    }

    pub fn event(&mut self, event: &Event) -> io::Result<()> {
        match event {
            Event::Port(port) => self.port(port),
            Event::Host(host) => self.host(host),
        }
    }

    fn port(&mut self, port: &PortResult) -> io::Result<()> {
        match self.format {
            Format::Text => {
                if self.show == Show::Open && port.state.as_str() != "open" {
                    return Ok(());
                }
                let rtt = match port.rtt_ms {
                    Some(ms) => format!("{ms}ms"),
                    None => "-".into(),
                };
                writeln!(
                    self.inner,
                    "{}  {}/tcp  {}  {:.2}  {rtt}",
                    port.ip,
                    port.port,
                    port.state.as_str(),
                    port.confidence
                )?;
            }
            Format::Txt => {
                let rtt = match port.rtt_ms {
                    Some(ms) => ms.to_string(),
                    None => "-".into(),
                };
                writeln!(
                    self.inner,
                    "{}\t{}\ttcp\t{}\t{:.3}\t{}\t{}\t{}",
                    port.ip,
                    port.port,
                    port.state.as_str(),
                    port.confidence,
                    port.attempts,
                    rtt,
                    port.reason.as_str()
                )?;
            }
            Format::Json => {
                let line = serde_json::json!({
                    "type": "port",
                    "ip": port.ip.to_string(),
                    "port": port.port,
                    "proto": "tcp",
                    "state": port.state.as_str(),
                    "confidence": round4(port.confidence),
                    "attempts": port.attempts,
                    "rtt_ms": port.rtt_ms,
                    "reason": port.reason.as_str(),
                });
                writeln!(self.inner, "{line}")?;
            }
        }
        self.inner.flush()
    }

    fn host(&mut self, host: &HostSkip) -> io::Result<()> {
        match self.format {
            Format::Text => {
                writeln!(
                    self.inner,
                    "# {}  no-response  confidence {:.2}  probed {}  skipped {}",
                    host.ip,
                    host.confidence,
                    host.probed,
                    host.skipped
                )?;
            }
            Format::Txt => {}
            Format::Json => {
                let line = serde_json::json!({
                    "type": "host",
                    "ip": host.ip.to_string(),
                    "state": "no-response",
                    "confidence": round4(host.confidence),
                    "probed": host.probed,
                    "skipped": host.skipped,
                });
                writeln!(self.inner, "{line}")?;
            }
        }
        self.inner.flush()
    }

    pub fn summary(&mut self, summary: &Summary, elapsed: Duration) -> io::Result<()> {
        match self.format {
            Format::Text => {
                let line = text_summary(summary, elapsed);
                if self.summary_err {
                    let mut err = io::stderr();
                    writeln!(err, "{line}")?;
                    err.flush()?;
                } else {
                    writeln!(self.inner, "{line}")?;
                    self.inner.flush()?;
                }
            }
            Format::Txt => {}
            Format::Json => {
                let mut line = serde_json::json!({
                    "type": "summary",
                    "ports": summary.ports,
                    "open": summary.open,
                    "closed": summary.closed,
                    "filtered": summary.filtered,
                    "uncertain": summary.uncertain,
                    "elapsed_ms": elapsed.as_millis() as u64,
                    "eta_lo_ms": summary.eta_lo_ms,
                    "eta_hi_ms": summary.eta_hi_ms,
                    "seed": summary.seed,
                    "attempts": summary.attempts,
                    "min_confidence": summary.min_confidence,
                });
                if summary.skipped > 0 {
                    line["skipped"] = serde_json::json!(summary.skipped);
                }
                if !summary.closed_ports.is_empty() {
                    line["closed_ports"] = serde_json::json!(summary.closed_ports);
                }
                if !summary.resolved.is_empty() {
                    line["resolved"] = serde_json::json!(
                        summary
                            .resolved
                            .iter()
                            .map(|item| serde_json::json!({
                                "query": item.query,
                                "ips": item.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>()
                            }))
                            .collect::<Vec<_>>()
                    );
                }
                writeln!(self.inner, "{line}")?;
                self.inner.flush()?;
            }
        };
        Ok(())
    }
}

fn text_summary(summary: &Summary, elapsed: Duration) -> String {
    let time = format_elapsed(elapsed);
    let mut line = if summary.skipped > 0 {
        format!(
            "# {} ports  open {}  closed {}  filtered {}  uncertain {}  skipped {}  {}  seed {}",
            summary.ports,
            summary.open,
            summary.closed,
            summary.filtered,
            summary.uncertain,
            summary.skipped,
            time,
            summary.seed
        )
    } else {
        format!(
            "# {} ports  open {}  closed {}  filtered {}  uncertain {}  {}  seed {}",
            summary.ports,
            summary.open,
            summary.closed,
            summary.filtered,
            summary.uncertain,
            time,
            summary.seed
        )
    };
    if summary.closed_ports.is_empty() {
        return line;
    }
    if summary.closed_ports.len() <= 64 {
        let list = summary
            .closed_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        line.push_str(&format!("\n# closed {list}"));
    } else {
        line.push_str(&format!(
            "\n# closed {} ports; the list is in --show all or json",
            summary.closed_ports.len()
        ));
    }
    line
}

fn round4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}
