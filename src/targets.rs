use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn concurrency_from_limit(limit: u64) -> usize {
    ((limit.saturating_sub(64)) / 2).clamp(32, 512) as usize
}

pub fn system_concurrency() -> usize {
    concurrency_from_limit(fd_limit().unwrap_or(1024))
}

fn fd_limit() -> Option<u64> {
    #[repr(C)]
    struct Rlimit {
        cur: u64,
        max: u64,
    }
    extern "C" {
        fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32;
    }
    #[cfg(target_os = "linux")]
    const RLIMIT_NOFILE: i32 = 7;
    #[cfg(not(target_os = "linux"))]
    const RLIMIT_NOFILE: i32 = 8;

    unsafe {
        let mut r = Rlimit { cur: 0, max: 0 };
        if getrlimit(RLIMIT_NOFILE, &mut r) == 0 && r.cur > 0 {
            Some(r.cur)
        } else {
            None
        }
    }
}

pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("the port list is empty".into());
    }
    if spec == "-" {
        return Ok((1..=65535).collect());
    }
    let mut set = BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err("extra comma in the port list".into());
        }
        if part == "-" {
            set.extend(1..=65535u16);
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let start = parse_port(a)?;
            let end = parse_port(b)?;
            if start > end {
                return Err(format!("range {part} is reversed"));
            }
            set.extend(start..=end);
        } else {
            set.insert(parse_port(part)?);
        }
    }
    if set.is_empty() {
        return Err("the port list is empty".into());
    }
    Ok(set.into_iter().collect())
}

fn parse_port(raw: &str) -> Result<u16, String> {
    let raw = raw.trim();
    let port: u16 = raw
        .parse()
        .map_err(|_| format!("invalid port: {raw}"))?;
    if port == 0 {
        return Err("port 0 is not valid".into());
    }
    Ok(port)
}

pub fn subtract_ports(ports: Vec<u16>, exclude: &[u16]) -> Vec<u16> {
    if exclude.is_empty() {
        return ports;
    }
    let skip: BTreeSet<u16> = exclude.iter().copied().collect();
    ports.into_iter().filter(|p| !skip.contains(p)).collect()
}

const MAX_ADDRS: u128 = 65_536;

pub fn expand_ip_spec(spec: &str) -> Result<Vec<IpAddr>, String> {
    let spec = spec.trim();
    if let Some((addr, prefix)) = spec.split_once('/') {
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| format!("invalid prefix in {spec}"))?;
        if let Ok(v4) = addr.parse::<Ipv4Addr>() {
            return expand_v4(v4, prefix);
        }
        if let Ok(v6) = addr.parse::<Ipv6Addr>() {
            return expand_v6(v6, prefix);
        }
        return Err(format!("invalid address in {spec}"));
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    Err(format!("not an IP or a CIDR: {spec}"))
}

fn expand_v4(addr: Ipv4Addr, prefix: u32) -> Result<Vec<IpAddr>, String> {
    if prefix > 32 {
        return Err(format!("IPv4 prefix /{prefix} does not exist"));
    }
    if prefix < 16 {
        return Err(format!(
            "range /{prefix} is over {MAX_ADDRS} addresses; the maximum is /16"
        ));
    }
    let count = 1u32 << (32 - prefix);
    let base = u32::from(addr) & !(count.wrapping_sub(1));
    Ok((0..count)
        .map(|i| IpAddr::V4(Ipv4Addr::from(base.wrapping_add(i))))
        .collect())
}

fn expand_v6(addr: Ipv6Addr, prefix: u32) -> Result<Vec<IpAddr>, String> {
    if prefix > 128 {
        return Err(format!("IPv6 prefix /{prefix} does not exist"));
    }
    let host_bits = 128 - prefix;
    if host_bits > 16 {
        return Err(format!(
            "range /{prefix} is over {MAX_ADDRS} addresses; the IPv6 maximum is /112"
        ));
    }
    let count = 1u128 << host_bits;
    let base = u128::from(addr) & !((count - 1) as u128);
    Ok((0..count)
        .map(|i| IpAddr::V6(Ipv6Addr::from(base + i)))
        .collect())
}

/// SplitMix64. The seed is printed in the summary so the same shuffle can be repeated.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
}

pub fn shuffle(ports: &mut [u16], seed: u64) {
    if ports.len() < 2 {
        return;
    }
    let mut rng = SplitMix64::new(seed);
    for i in (1..ports.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        ports.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_dash() {
        assert_eq!(parse_ports("80,443").unwrap(), vec![80, 443]);
        assert_eq!(parse_ports("2-4").unwrap(), vec![2, 3, 4]);
        assert_eq!(parse_ports("-").unwrap().len(), 65535);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("5-2").is_err());
        let left = subtract_ports(vec![1, 2, 3], &[2]);
        assert_eq!(left, vec![1, 3]);
    }

    #[test]
    fn cidr_limits() {
        let ips = expand_ip_spec("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 4);
        assert!(expand_ip_spec("10.0.0.0/8").is_err());
        assert_eq!(expand_ip_spec("127.0.0.1").unwrap(), vec![IpAddr::from([127, 0, 0, 1])]);
    }

    #[test]
    fn concurrency_clamp() {
        assert_eq!(concurrency_from_limit(10_000), 512);
        assert_eq!(concurrency_from_limit(200), 68);
        assert_eq!(concurrency_from_limit(64), 32);
    }

    #[test]
    fn shuffle_is_stable() {
        let mut a = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut b = a.clone();
        shuffle(&mut a, 7);
        shuffle(&mut b, 7);
        assert_eq!(a, b);
        assert_ne!(a, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
