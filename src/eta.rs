/// Wall time still left.
///
/// `t_silent` is the sum of the waits for a port that spends the whole budget.
/// `residual` is the sum, over in-flight attempts, of the time each one has left.
pub fn eta_seconds(
    remaining: u64,
    q: f64,
    rtt_p95: f64,
    t_silent: f64,
    concurrency: u32,
    residual: f64,
) -> f64 {
    let conc = concurrency.max(1) as f64;
    let q = q.clamp(0.0, 1.0);
    let e_slot = (1.0 - q) * rtt_p95.max(0.0) + q * t_silent.max(0.0);
    (remaining as f64 * e_slot + residual.max(0.0)) / conc
}

pub fn eta_lo(remaining: u64, rtt_p95: f64, concurrency: u32) -> f64 {
    remaining as f64 * rtt_p95.max(0.0) / concurrency.max(1) as f64
}

pub fn eta_hi(remaining: u64, t_silent: f64, concurrency: u32) -> f64 {
    remaining as f64 * t_silent.max(0.0) / concurrency.max(1) as f64
}

/// 95th percentile by nearest rank. Fewer than 20 samples is not enough.
pub fn percentile_95(samples: &[f64]) -> Option<f64> {
    if samples.len() < 20 {
        return None;
    }
    let mut v = samples.to_vec();
    let idx = ((v.len() - 1) as f64 * 0.95).round() as usize;
    v.select_nth_unstable_by(idx, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    Some(v[idx])
}

/// `q` starts at 0.5 and, from the 32nd finished port, is the real fraction.
pub fn silent_fraction(done: u64, silent: u64) -> f64 {
    if done < 32 {
        0.5
    } else if done == 0 {
        0.5
    } else {
        (silent as f64 / done as f64).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_silent_and_all_decisive() {
        let t = 0.500 + 0.750 + 1.125;
        let silent = eta_seconds(1000, 1.0, 0.020, t, 100, 0.0);
        assert!((silent - 23.75).abs() < 1e-9);

        let fast = eta_seconds(1000, 0.0, 0.020, t, 100, 0.0);
        assert!((fast - 0.20).abs() < 1e-9);

        assert!((eta_hi(1000, t, 100) - 23.75).abs() < 1e-9);
        assert!((eta_lo(1000, 0.020, 100) - 0.20).abs() < 1e-9);
    }

    #[test]
    fn q_stays_half_until_thirty_two() {
        assert_eq!(silent_fraction(31, 31), 0.5);
        assert!((silent_fraction(32, 8) - 0.25).abs() < 1e-12);
    }
}
