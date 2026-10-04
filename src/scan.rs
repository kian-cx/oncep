use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;

use crate::confidence::{self, Reason, State, Verdict};
use crate::eta::{self, eta_hi, eta_lo, eta_seconds, percentile_95};
use crate::probe::{LocalError, Observation, Probe};
use crate::progress::LiveStats;
use crate::rtt::RttEstimator;

const PER_HOST: usize = 64;
const MUTE_PORTS: usize = 24;
/// Decisive replies before a silence may stop on confidence.
const MEASURED_ATTEMPTS: u32 = 8;
const RESOURCE_TRIES: u32 = 20;
const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 8080, 8443,
];

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub attempts: u32,
    pub insist: bool,
    pub min_confidence: f64,
    pub timeout_max: Duration,
    pub concurrency: usize,
    pub rate: u32,
    pub seed: u64,
    pub ordered: bool,
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub ip: IpAddr,
    pub ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct PortResult {
    pub ip: IpAddr,
    pub port: u16,
    pub state: State,
    pub confidence: f64,
    pub attempts: u32,
    pub rtt_ms: Option<u64>,
    pub reason: Reason,
}

#[derive(Debug, Clone)]
pub struct HostSkip {
    pub ip: IpAddr,
    pub confidence: f64,
    pub probed: u32,
    pub skipped: u32,
}

#[derive(Debug, Clone)]
pub enum Event {
    Port(PortResult),
    Host(HostSkip),
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub ports: u64,
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub uncertain: u64,
    pub skipped: u64,
    pub eta_lo_ms: u64,
    pub eta_hi_ms: u64,
    pub seed: u64,
    pub attempts: u32,
    pub min_confidence: f64,
    pub losses: u64,
    pub answered_attempts: u64,
    pub closed_ports: Vec<u16>,
    pub resolved: Vec<ResolvedName>,
}

#[derive(Debug, Clone)]
pub struct ResolvedName {
    pub query: String,
    pub ips: Vec<IpAddr>,
}

struct Job {
    addr: SocketAddr,
    tries: u32,
    connects: u32,
    refused: u32,
    timeouts: u32,
    resource_tries: u32,
    first_timeout: bool,
    rtt: Option<Duration>,
    sample: bool,
}

struct HostQ {
    ip: IpAddr,
    ports: VecDeque<Job>,
    rest: VecDeque<Job>,
    sample_left: u32,
    released: bool,
    inflight: usize,
    rtt: RttEstimator,
    losses: u32,
    answered_attempts: u32,
    decisive: u32,
    finished: u32,
    mute_attempts: u32,
    aborted: bool,
    announced: bool,
    skipped: u32,
}

struct Done {
    id: u64,
    host_idx: usize,
    job: Job,
    obs: Result<Observation, LocalError>,
}

struct Bucket {
    rate: f64,
    tokens: f64,
    burst: f64,
    updated: Instant,
}

impl Bucket {
    fn new(rate: u32, burst: usize) -> Self {
        let burst = burst.max(1) as f64;
        Self {
            rate: rate.max(1) as f64,
            tokens: burst,
            burst,
            updated: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.updated).as_secs_f64();
        self.updated = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
    }

    async fn acquire(this: &Mutex<Self>) {
        loop {
            let wait = {
                let mut bucket = this.lock().await;
                bucket.refill();
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }
                let need = 1.0 - bucket.tokens;
                Duration::from_secs_f64(need / bucket.rate)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

pub async fn scan<P: Probe + 'static>(
    targets: Vec<Target>,
    cfg: ScanConfig,
    probe: P,
    tx: mpsc::UnboundedSender<Event>,
    stats: Arc<LiveStats>,
) -> Summary {
    let probe = Arc::new(probe);
    let mut hosts: Vec<HostQ> = targets
        .into_iter()
        .map(|t| host_queue(t, cfg.force, cfg.timeout_max))
        .collect();

    let total: u64 = hosts
        .iter()
        .map(|h| (h.ports.len() + h.rest.len()) as u64)
        .sum();
    stats.total.store(total, Ordering::Relaxed);

    let bucket = Arc::new(Mutex::new(Bucket::new(cfg.rate, cfg.concurrency)));
    let mut join: JoinSet<Done> = JoinSet::new();
    let mut inflight: usize = 0;
    let mut cursor: usize = 0;
    let mut next_id: u64 = 1;
    let residual: Arc<Mutex<Vec<(u64, Instant, Duration)>>> = Arc::new(Mutex::new(Vec::new()));

    let mut global_rtt = RttEstimator::new(cfg.timeout_max);
    let mut rtt_samples: Vec<f64> = Vec::new();
    let mut silent_done: u64 = 0;
    let mut probed_done: u64 = 0;
    let mut open = 0u64;
    let mut closed = 0u64;
    let mut closed_ports: Vec<u16> = Vec::new();
    let mut filtered = 0u64;
    let mut uncertain = 0u64;
    let mut skipped = 0u64;
    let mut losses = 0u64;
    let mut answered_attempts = 0u64;

    loop {
        while inflight < cfg.concurrency {
            let Some((host_idx, job)) = take_job(&mut hosts, &mut cursor) else {
                break;
            };
            hosts[host_idx].inflight += 1;
            inflight += 1;
            Bucket::acquire(&bucket).await;
            let timeout = hosts[host_idx].rtt.attempt_timeout(job.tries + 1);
            let id = next_id;
            next_id += 1;
            residual.lock().await.push((id, Instant::now(), timeout));
            let probe = Arc::clone(&probe);
            let addr = job.addr;
            join.spawn(async move {
                let obs = probe.attempt(addr, timeout).await;
                Done {
                    id,
                    host_idx,
                    job,
                    obs,
                }
            });
        }

        if inflight == 0 {
            break;
        }

        let Some(joined) = join.join_next().await else {
            break;
        };
        inflight = inflight.saturating_sub(1);
        let Ok(done) = joined else {
            continue;
        };
        residual.lock().await.retain(|(id, _, _)| *id != done.id);
        let host = &mut hosts[done.host_idx];
        host.inflight = host.inflight.saturating_sub(1);

        match done.obs {
            Err(LocalError::Resource) => {
                let mut job = done.job;
                job.resource_tries += 1;
                if job.resource_tries >= RESOURCE_TRIES {
                    finish_unreachable(host, &job, &tx);
                    uncertain += 1;
                    probed_done += 1;
                    settle_sample(host, cfg.force, &tx, &mut skipped);
                } else {
                    host.ports.push_front(job);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
            Ok(Observation::Unreachable) => {
                finish_unreachable(host, &done.job, &tx);
                uncertain += 1;
                probed_done += 1;
                settle_sample(host, cfg.force, &tx, &mut skipped);
            }
            Ok(obs) => {
                let mut job = done.job;
                apply_obs(&mut job, &obs, host, &mut global_rtt, &mut rtt_samples);
                let decisive_now = job.connects > 0 || job.refused > 0;
                let early = !cfg.insist
                    && ((job.connects > 0 && job.refused == 0)
                        || (job.refused > 0 && job.connects == 0));
                let p_loss = confidence::p_loss_hi(host.losses, host.answered_attempts);
                let measured = host.answered_attempts >= MEASURED_ATTEMPTS;
                let silent_done_early = !cfg.insist
                    && !decisive_now
                    && measured
                    && job.timeouts > 0
                    && confidence::classify(
                        job.connects,
                        job.refused,
                        job.timeouts,
                        p_loss,
                        cfg.min_confidence,
                    )
                    .state
                        == State::Filtered;
                if early || silent_done_early || job.tries >= cfg.attempts {
                    let verdict = confidence::classify(
                        job.connects,
                        job.refused,
                        job.timeouts,
                        p_loss,
                        cfg.min_confidence,
                    );
                    if decisive_now {
                        host.losses += job.timeouts;
                        host.answered_attempts += job.tries;
                        host.decisive += 1;
                        losses += job.timeouts as u64;
                        answered_attempts += job.tries as u64;
                    } else {
                        host.mute_attempts += job.tries;
                    }
                    if job.first_timeout {
                        silent_done += 1;
                    }
                    probed_done += 1;
                    host.finished += 1;
                    count_state(
                        verdict.state,
                        &mut open,
                        &mut closed,
                        &mut filtered,
                        &mut uncertain,
                    );
                    if verdict.state == State::Closed {
                        closed_ports.push(job.addr.port());
                    }
                    let _ = tx.send(Event::Port(port_result(host.ip, &job, verdict)));
                    note_sample(host, &job);
                    settle_sample(host, cfg.force, &tx, &mut skipped);
                } else {
                    host.ports.push_back(job);
                }
            }
        }

        let settled = probed_done + skipped;
        let active_hosts = hosts
            .iter()
            .filter(|h| !h.aborted && (!h.ports.is_empty() || h.inflight > 0))
            .count()
            .max(1);
        let effective = cfg.concurrency.min(active_hosts * PER_HOST).max(1);
        update_eta(
            &stats,
            &cfg,
            effective,
            &global_rtt,
            &rtt_samples,
            silent_done,
            probed_done,
            total.saturating_sub(settled),
            &residual,
        )
        .await;
        stats.settled.store(settled, Ordering::Relaxed);
        stats.open.store(open, Ordering::Relaxed);
    }

    // Queues nobody started (nothing should be left).
    for host in &mut hosts {
        let n = (host.ports.len() + host.rest.len()) as u64;
        if n > 0 {
            host.ports.clear();
            host.rest.clear();
            skipped += n;
        }
    }

    closed_ports.sort_unstable();
    closed_ports.dedup();
    Summary {
        ports: total,
        open,
        closed,
        filtered,
        uncertain,
        skipped,
        eta_lo_ms: stats.eta_lo_ms.load(Ordering::Relaxed),
        eta_hi_ms: stats.eta_hi_ms.load(Ordering::Relaxed),
        seed: cfg.seed,
        attempts: cfg.attempts,
        min_confidence: cfg.min_confidence,
        losses,
        answered_attempts,
        closed_ports,
        resolved: Vec::new(),
    }
}

fn host_queue(target: Target, force: bool, timeout_max: Duration) -> HostQ {
    let sample_list = discovery_sample(&target.ports, MUTE_PORTS);
    let sample_set: BTreeSet<u16> = sample_list.iter().copied().collect();
    let mut by_port: HashMap<u16, Job> = HashMap::new();
    for port in &target.ports {
        by_port.insert(
            *port,
            Job {
                addr: SocketAddr::new(target.ip, *port),
                tries: 0,
                connects: 0,
                refused: 0,
                timeouts: 0,
                resource_tries: 0,
                first_timeout: false,
                rtt: None,
                sample: sample_set.contains(port),
            },
        );
    }
    let mut ports = VecDeque::new();
    for port in &sample_list {
        if let Some(job) = by_port.remove(port) {
            ports.push_back(job);
        }
    }
    let mut rest = VecDeque::new();
    for port in &target.ports {
        if let Some(job) = by_port.remove(port) {
            rest.push_back(job);
        }
    }
    let sample_left = ports.len() as u32;
    let released = force;
    if force {
        ports.extend(rest.drain(..));
    }
    HostQ {
        ip: target.ip,
        ports,
        rest,
        sample_left,
        released,
        inflight: 0,
        rtt: RttEstimator::new(timeout_max),
        losses: 0,
        answered_attempts: 0,
        decisive: 0,
        finished: 0,
        mute_attempts: 0,
        aborted: false,
        announced: false,
        skipped: 0,
    }
}

/// Ports that decide whether the host is up: the common ones present in the
/// list, and the rest spread from one end of the range to the other.
pub fn discovery_sample(ports: &[u16], k: usize) -> Vec<u16> {
    if ports.is_empty() || k == 0 {
        return Vec::new();
    }
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let k = k.min(sorted.len());
    let have: BTreeSet<u16> = sorted.iter().copied().collect();
    let mut out = Vec::with_capacity(k);
    out.push(sorted[0]);
    if k > 1 {
        if let Some(last) = sorted.last().copied() {
            if !out.contains(&last) {
                out.push(last);
            }
        }
    }
    for port in COMMON_PORTS {
        if out.len() == k {
            break;
        }
        if have.contains(port) {
            out.push(*port);
        }
    }
    let n = sorted.len();
    for i in 0..k {
        if out.len() == k {
            break;
        }
        let idx = if k == 1 { 0 } else { i * (n - 1) / (k - 1) };
        let port = sorted[idx];
        if !out.contains(&port) {
            out.push(port);
        }
    }
    if out.len() < k {
        for port in sorted {
            if out.len() == k {
                break;
            }
            if !out.contains(&port) {
                out.push(port);
            }
        }
    }
    out
}

fn take_job(hosts: &mut [HostQ], cursor: &mut usize) -> Option<(usize, Job)> {
    let n = hosts.len();
    if n == 0 {
        return None;
    }
    for k in 0..n {
        let i = (*cursor + k) % n;
        if hosts[i].aborted || hosts[i].inflight >= PER_HOST {
            continue;
        }
        if let Some(job) = hosts[i].ports.pop_front() {
            *cursor = i + 1;
            return Some((i, job));
        }
    }
    None
}

fn apply_obs(
    job: &mut Job,
    obs: &Observation,
    host: &mut HostQ,
    global_rtt: &mut RttEstimator,
    samples: &mut Vec<f64>,
) {
    job.tries += 1;
    match obs {
        Observation::Connected { rtt } => {
            job.connects += 1;
            job.rtt = Some(*rtt);
            host.rtt.observe(*rtt);
            global_rtt.observe(*rtt);
            samples.push(rtt.as_secs_f64());
        }
        Observation::Refused { rtt } => {
            job.refused += 1;
            job.rtt = Some(*rtt);
            host.rtt.observe(*rtt);
            global_rtt.observe(*rtt);
            samples.push(rtt.as_secs_f64());
        }
        Observation::Timeout => {
            job.timeouts += 1;
            if job.tries == 1 {
                job.first_timeout = true;
            }
        }
        Observation::Unreachable => {}
    }
}

fn finish_unreachable(host: &mut HostQ, job: &Job, tx: &mpsc::UnboundedSender<Event>) {
    host.finished += 1;
    host.mute_attempts += job.tries.max(1);
    note_sample(host, job);
    let _ = tx.send(Event::Port(PortResult {
        ip: host.ip,
        port: job.addr.port(),
        state: State::Uncertain,
        confidence: 0.0,
        attempts: job.tries.max(1),
        rtt_ms: None,
        reason: Reason::Unreachable,
    }));
}

fn note_sample(host: &mut HostQ, job: &Job) {
    if job.sample {
        host.sample_left = host.sample_left.saturating_sub(1);
    }
}

/// Releases the rest once the sample has seen a reply. If the whole sample
/// finished in silence, the remainder is skipped.
fn settle_sample(host: &mut HostQ, force: bool, tx: &mpsc::UnboundedSender<Event>, skipped: &mut u64) {
    if host.decisive > 0 && !host.released {
        host.ports.extend(host.rest.drain(..));
        host.released = true;
    }
    if force || host.released || host.announced || host.sample_left > 0 {
        return;
    }
    let n = host.rest.len() as u32;
    host.rest.clear();
    host.aborted = true;
    host.announced = true;
    host.skipped += n;
    *skipped += n as u64;
    if n == 0 {
        return;
    }
    let _ = tx.send(Event::Host(HostSkip {
        ip: host.ip,
        confidence: confidence::confidence_no_response(host.mute_attempts),
        probed: host.finished,
        skipped: n,
    }));
}

fn port_result(ip: IpAddr, job: &Job, verdict: Verdict) -> PortResult {
    PortResult {
        ip,
        port: job.addr.port(),
        state: verdict.state,
        confidence: verdict.confidence,
        attempts: job.tries,
        rtt_ms: job.rtt.map(|d| d.as_millis() as u64),
        reason: verdict.reason,
    }
}

fn count_state(state: State, open: &mut u64, closed: &mut u64, filtered: &mut u64, uncertain: &mut u64) {
    match state {
        State::Open => *open += 1,
        State::Closed => *closed += 1,
        State::Filtered => *filtered += 1,
        State::Uncertain => *uncertain += 1,
    }
}

async fn update_eta(
    stats: &LiveStats,
    cfg: &ScanConfig,
    effective_concurrency: usize,
    rtt: &RttEstimator,
    samples: &[f64],
    silent_done: u64,
    probed_done: u64,
    remaining: u64,
    residual: &Mutex<Vec<(u64, Instant, Duration)>>,
) {
    let q = eta::silent_fraction(probed_done, silent_done);
    let rtt_p95 = percentile_95(samples).unwrap_or_else(|| rtt.rto().as_secs_f64());
    let t_silent: f64 = (1..=cfg.attempts)
        .map(|n| rtt.attempt_timeout(n).as_secs_f64())
        .sum();
    let now = Instant::now();
    let residual_secs: f64 = residual
        .lock()
        .await
        .iter()
        .map(|(_, start, budget)| budget.as_secs_f64() - now.duration_since(*start).as_secs_f64())
        .map(|left| left.max(0.0))
        .sum();
    let secs = eta_seconds(
        remaining,
        q,
        rtt_p95,
        t_silent,
        effective_concurrency as u32,
        residual_secs,
    );
    stats
        .eta_ms
        .store((secs * 1000.0).round() as u64, Ordering::Relaxed);
    stats
        .approx
        .store(probed_done < 32, Ordering::Relaxed);
    if remaining > 0 && !stats.eta_frozen.load(Ordering::Relaxed) {
        let conc = effective_concurrency as u32;
        stats
            .eta_lo_ms
            .store((eta_lo(remaining, rtt_p95, conc) * 1000.0).round() as u64, Ordering::Relaxed);
        stats
            .eta_hi_ms
            .store((eta_hi(remaining, t_silent, conc) * 1000.0).round() as u64, Ordering::Relaxed);
        if probed_done >= 32 {
            stats.eta_frozen.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Observation, ScriptedProbe};
    use std::net::{IpAddr, Ipv4Addr};

    fn cfg(attempts: u32, concurrency: usize, force: bool) -> ScanConfig {
        ScanConfig {
            attempts,
            insist: false,
            min_confidence: 0.95,
            timeout_max: Duration::from_millis(2000),
            concurrency,
            rate: 1_000_000,
            seed: 1,
            ordered: true,
            force,
        }
    }

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    async fn run_one(target: Target, cfg: ScanConfig, probe: ScriptedProbe) -> (Vec<Event>, Summary) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let total: u64 = target.ports.len() as u64;
        let stats = Arc::new(LiveStats::new(total));
        let scan_fut = scan(vec![target], cfg, probe, tx, stats);
        let mut events = Vec::new();
        let collect = async {
            while let Some(ev) = rx.recv().await {
                events.push(ev);
            }
            events
        };
        let (events, summary) = tokio::join!(collect, scan_fut);
        (events, summary)
    }

    #[tokio::test]
    async fn retries_timeouts_then_open_counts_loss() {
        let addr = SocketAddr::new(ip(), 9);
        let probe = ScriptedProbe::new();
        probe.push(addr, Observation::Timeout);
        probe.push(addr, Observation::Timeout);
        probe.push(
            addr,
            Observation::Connected {
                rtt: Duration::from_millis(12),
            },
        );
        let (events, summary) = run_one(
            Target {
                ip: ip(),
                ports: vec![9],
            },
            cfg(3, 1, true),
            probe,
        )
        .await;
        let Event::Port(port) = &events[0] else {
            panic!("expected a port");
        };
        assert_eq!(port.state, State::Open);
        assert!((port.confidence - 0.99).abs() < 1e-9);
        assert_eq!(port.attempts, 3);
        assert_eq!(summary.losses, 2);
        assert_eq!(summary.answered_attempts, 3);
        assert_eq!(summary.open, 1);
    }

    #[tokio::test]
    async fn mute_host_skips_the_rest() {
        let probe = ScriptedProbe::new();
        let ports: Vec<u16> = (1..=30).collect();
        let (events, summary) = run_one(
            Target {
                ip: ip(),
                ports,
            },
            cfg(1, 1, false),
            probe,
        )
        .await;
        let ports_n = events.iter().filter(|e| matches!(e, Event::Port(_))).count();
        let host = events.iter().find_map(|e| match e {
            Event::Host(h) => Some(h),
            _ => None,
        });
        let host = host.expect("silent host");
        assert_eq!(ports_n, 24);
        assert_eq!(host.probed, 24);
        assert_eq!(host.skipped, 6);
        assert_eq!(summary.skipped, 6);
        assert_eq!(summary.uncertain, 24);
        assert_eq!(summary.ports, 30);
    }

    #[tokio::test]
    async fn localhost_open_and_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, _)) = listener.accept().await {
                    drop(sock);
                }
            }
        });
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        };
        let (tx, mut rx) = mpsc::unbounded_channel();
        let stats = Arc::new(LiveStats::new(2));
        let cfg = cfg(1, 4, true);
        let summary = scan(
            vec![Target {
                ip: ip(),
                ports: vec![open_port, closed],
            }],
            cfg,
            crate::probe::TcpProbe,
            tx,
            stats,
        );
        let mut events = Vec::new();
        let collect = async {
            while let Some(ev) = rx.recv().await {
                events.push(ev);
            }
            events
        };
        let (events, summary) = tokio::join!(collect, summary);
        let mut states = events
            .iter()
            .filter_map(|e| match e {
                Event::Port(p) => Some((p.port, p.state, p.confidence, p.attempts)),
                _ => None,
            })
            .collect::<Vec<_>>();
        states.sort_by_key(|s| s.0);
        let open = states.iter().find(|s| s.0 == open_port).unwrap();
        let shut = states.iter().find(|s| s.0 == closed).unwrap();
        assert_eq!(open.1, State::Open);
        assert!((open.2 - 0.99).abs() < 1e-9);
        assert_eq!(open.3, 1);
        assert_eq!(shut.1, State::Closed);
        assert!((shut.2 - 0.97).abs() < 1e-9);
        assert_eq!(summary.open, 1);
        assert_eq!(summary.closed, 1);
        assert_eq!(summary.closed_ports, vec![closed]);
    }

    #[test]
    fn sample_covers_common_ports_and_both_ends() {
        let ports: Vec<u16> = (1..=1024).collect();
        let sample = discovery_sample(&ports, 24);
        assert_eq!(sample.len(), 24);
        assert!(sample.contains(&1));
        assert!(sample.contains(&80));
        assert!(sample.contains(&443));
        assert!(sample.contains(&1024));
    }

    #[tokio::test]
    async fn open_outside_the_sample_is_still_scanned() {
        let ports: Vec<u16> = (1..=40).collect();
        let sample = discovery_sample(&ports, 24);
        let rest = ports.iter().copied().find(|p| !sample.contains(p)).unwrap();
        let probe = ScriptedProbe::new();
        for port in &ports {
            let addr = SocketAddr::new(ip(), *port);
            if *port == rest {
                probe.push(
                    addr,
                    Observation::Connected {
                        rtt: Duration::from_millis(5),
                    },
                );
            } else {
                probe.push(
                    addr,
                    Observation::Refused {
                        rtt: Duration::from_millis(5),
                    },
                );
            }
        }
        let (events, summary) = run_one(
            Target {
                ip: ip(),
                ports,
            },
            cfg(3, 1, false),
            probe,
        )
        .await;
        assert!(events.iter().any(|e| matches!(e, Event::Port(p) if p.port == rest && p.state == State::Open)));
        assert_eq!(summary.skipped, 0);
        assert_eq!(summary.ports, 40);
        assert!(events.iter().all(|e| !matches!(e, Event::Host(_))));
    }

    #[tokio::test]
    async fn mute_sample_does_not_probe_the_open_port_outside_it() {
        let ports: Vec<u16> = (1..=40).collect();
        let sample = discovery_sample(&ports, 24);
        let hidden = ports.iter().copied().find(|p| !sample.contains(p)).unwrap();
        let probe = ScriptedProbe::new();
        probe.push(
            SocketAddr::new(ip(), hidden),
            Observation::Connected {
                rtt: Duration::from_millis(5),
            },
        );
        let (events, summary) = run_one(
            Target { ip: ip(), ports },
            cfg(1, 1, false),
            probe,
        )
        .await;
        assert!(events.iter().all(|e| !matches!(e, Event::Port(p) if p.port == hidden)));
        assert!(summary.skipped >= 1);
        assert_eq!(summary.open, 0);
    }

    #[tokio::test]
    async fn measured_host_stops_silence_before_the_budget() {
        let ports: Vec<u16> = (1..=40).collect();
        let sample = discovery_sample(&ports, 24);
        let silent = ports.iter().copied().find(|p| !sample.contains(p)).unwrap();
        let probe = ScriptedProbe::new();
        for port in &ports {
            let addr = SocketAddr::new(ip(), *port);
            if *port == silent {
                probe.push(addr, Observation::Timeout);
                probe.push(addr, Observation::Timeout);
                probe.push(
                    addr,
                    Observation::Connected {
                        rtt: Duration::from_millis(5),
                    },
                );
            } else {
                probe.push(
                    addr,
                    Observation::Refused {
                        rtt: Duration::from_millis(5),
                    },
                );
            }
        }
        let (events, _) = run_one(
            Target { ip: ip(), ports },
            cfg(3, 1, false),
            probe,
        )
        .await;
        let port = events.iter().find_map(|e| match e {
            Event::Port(p) if p.port == silent => Some(p),
            _ => None,
        }).expect("silent port");
        assert_eq!(port.state, State::Filtered);
        assert_eq!(port.attempts, 2);
    }
}
