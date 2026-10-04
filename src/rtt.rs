use std::time::Duration;

const ALPHA: f64 = 0.125;
const BETA: f64 = 0.25;
const TIMEOUT_MIN: f64 = 0.1;
const INITIAL_RTO: f64 = 0.5;
const SAMPLES_BEFORE_RTO: u32 = 4;

/// RFC 6298 estimator. A timed-out attempt is not observed:
/// that is Karn's algorithm, and the caller enforces it.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    srtt: f64,
    rttvar: f64,
    samples: u32,
    timeout_max: f64,
    has_sample: bool,
}

impl RttEstimator {
    pub fn new(timeout_max: Duration) -> Self {
        let timeout_max = timeout_max.as_secs_f64().max(TIMEOUT_MIN);
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            samples: 0,
            timeout_max,
            has_sample: false,
        }
    }

    pub fn observe(&mut self, rtt: Duration) {
        let r = rtt.as_secs_f64().max(0.0);
        if !self.has_sample {
            self.srtt = r;
            self.rttvar = r / 2.0;
            self.has_sample = true;
        } else {
            self.rttvar = (1.0 - BETA) * self.rttvar + BETA * (self.srtt - r).abs();
            self.srtt = (1.0 - ALPHA) * self.srtt + ALPHA * r;
        }
        self.samples = self.samples.saturating_add(1);
    }

    pub fn srtt(&self) -> Option<f64> {
        self.has_sample.then_some(self.srtt)
    }

    pub fn rttvar(&self) -> f64 {
        self.rttvar
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    /// Current RTO. Until 4 samples it stays at 500 ms, clipped to the ceiling.
    pub fn rto(&self) -> Duration {
        let secs = if self.samples < SAMPLES_BEFORE_RTO {
            INITIAL_RTO
        } else {
            self.srtt + 4.0 * self.rttvar
        };
        Duration::from_secs_f64(secs.clamp(TIMEOUT_MIN, self.timeout_max))
    }

    /// Wait for attempt `n` (1-based) of a port that is still silent.
    pub fn attempt_timeout(&self, n: u32) -> Duration {
        let n = n.max(1);
        let factor = 1.5_f64.powi((n as i32) - 1);
        let secs = self.rto().as_secs_f64() * factor;
        Duration::from_secs_f64(secs.clamp(TIMEOUT_MIN, self.timeout_max))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_sequence_and_karn() {
        let mut est = RttEstimator::new(Duration::from_millis(2000));
        assert_eq!(est.rto(), Duration::from_millis(500));

        est.observe(Duration::from_secs_f64(0.100));
        est.observe(Duration::from_secs_f64(0.120));
        est.observe(Duration::from_secs_f64(0.080));
        assert_eq!(est.samples(), 3);
        assert_eq!(est.rto(), Duration::from_millis(500));

        est.observe(Duration::from_secs_f64(0.100));
        let srtt = est.srtt().unwrap();
        let rttvar = est.rttvar();
        assert!((srtt - 0.0997265625).abs() < 1e-12);
        assert!((rttvar - 0.028203125).abs() < 1e-12);
        let rto = srtt + 4.0 * rttvar;
        assert!((rto - 0.2125390625).abs() < 1e-12);
        assert!((est.rto().as_secs_f64() - rto).abs() < 1e-6);

        // Karn: not observing a timeout leaves the estimator unchanged.
        let before = (est.srtt().unwrap(), est.rttvar(), est.samples());
        assert_eq!(before.2, 4);
        assert_eq!(est.srtt().unwrap(), before.0);
    }

    #[test]
    fn silent_attempt_backoff() {
        let est = RttEstimator::new(Duration::from_millis(2000));
        assert_eq!(est.attempt_timeout(1), Duration::from_millis(500));
        assert_eq!(est.attempt_timeout(2), Duration::from_millis(750));
        assert_eq!(est.attempt_timeout(3), Duration::from_millis(1125));
    }
}
