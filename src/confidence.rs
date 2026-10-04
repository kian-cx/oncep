/// Published label. `uncertain` means the budget ran out
/// below `--min-confidence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Filtered,
    Uncertain,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
            State::Filtered => "filtered",
            State::Uncertain => "uncertain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Connected,
    Refused,
    Timeout,
    Unreachable,
    Mixed,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Connected => "connected",
            Reason::Refused => "refused",
            Reason::Timeout => "timeout",
            Reason::Unreachable => "unreachable",
            Reason::Mixed => "mixed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Verdict {
    pub state: State,
    pub confidence: f64,
    pub reason: Reason,
}

const P_FALSE_OPEN: f64 = 0.01;
const P_FALSE_CLOSED: f64 = 0.03;
const P_TIMEOUT_FILTERED: f64 = 0.98;

/// Upper 90% bound on loss, using only ports that answered.
/// Prior Beta(1, 9): cold, the quantile is 0.2257.
pub fn p_loss_hi(losses: u32, answered_attempts: u32) -> f64 {
    let alpha = 1.0 + losses as f64;
    let successes = answered_attempts.saturating_sub(losses) as f64;
    let beta = 9.0 + successes;
    beta_quantile(alpha, beta, 0.90)
}

pub fn classify(
    connects: u32,
    refused: u32,
    timeouts: u32,
    p_loss: f64,
    min_confidence: f64,
) -> Verdict {
    let (raw, confidence, reason) = if connects > 0 && refused == 0 {
        (
            State::Open,
            1.0 - P_FALSE_OPEN.powi(connects as i32),
            Reason::Connected,
        )
    } else if refused > 0 && connects == 0 {
        (
            State::Closed,
            1.0 - P_FALSE_CLOSED.powi(refused as i32),
            Reason::Refused,
        )
    } else if connects == 0 && refused == 0 && timeouts > 0 {
        (
            State::Filtered,
            timeout_confidence(timeouts, p_loss),
            Reason::Timeout,
        )
    } else if connects > 0 && refused > 0 {
        let (state, conf) = mixed_posterior(connects, refused, timeouts, p_loss);
        (state, conf, Reason::Mixed)
    } else {
        (State::Uncertain, 0.0, Reason::Timeout)
    };

    let shown3 = (confidence * 1000.0).round() / 1000.0;
    let state = if shown3 < min_confidence {
        State::Uncertain
    } else {
        raw
    };
    let confidence = (confidence * 10000.0).round() / 10000.0;
    Verdict {
        state,
        confidence,
        reason,
    }
}

pub fn timeout_confidence(k: u32, p_loss_hi: f64) -> f64 {
    if k == 0 {
        return 0.0;
    }
    let ratio = (p_loss_hi / P_TIMEOUT_FILTERED).clamp(0.0, 1.0e6);
    let odds_against = ratio.powi(k as i32);
    1.0 / (1.0 + odds_against)
}

/// k is the attempts spent on the silent sample.
pub fn confidence_no_response(mute_attempts: u32) -> f64 {
    let p = p_loss_hi(0, 0);
    timeout_confidence(mute_attempts, p)
}

fn mixed_posterior(connects: u32, refused: u32, timeouts: u32, p: f64) -> (State, f64) {
    let p = p.clamp(0.0, 0.999);
    let one_minus = 1.0 - p;
    let mut open = [0.97 * one_minus, 0.02 * one_minus, p];
    let mut closed = [0.01 * one_minus, 0.96 * one_minus, p];
    let mut filtered = [0.01, 0.01, 0.98];
    normalize(&mut open);
    normalize(&mut closed);
    normalize(&mut filtered);

    let like = |col: [f64; 3]| {
        col[0].powi(connects as i32) * col[1].powi(refused as i32) * col[2].powi(timeouts as i32)
    };
    let lo = like(open);
    let lc = like(closed);
    let lf = like(filtered);
    let sum = lo + lc + lf;
    if sum <= 0.0 || !sum.is_finite() {
        return (State::Uncertain, 0.0);
    }
    let (state, mass) = if lo >= lc && lo >= lf {
        (State::Open, lo)
    } else if lc >= lo && lc >= lf {
        (State::Closed, lc)
    } else {
        (State::Filtered, lf)
    };
    (state, mass / sum)
}

fn normalize(xs: &mut [f64; 3]) {
    let sum: f64 = xs.iter().sum();
    if sum > 0.0 && sum.is_finite() {
        for x in xs.iter_mut() {
            *x /= sum;
        }
    }
}

/// Quantile of Beta(α, β) by 40 bisections of the regularized incomplete beta.
pub fn beta_quantile(alpha: f64, beta: f64, p: f64) -> f64 {
    if alpha <= 1.0 + f64::EPSILON {
        return 1.0 - (1.0 - p).powf(1.0 / beta);
    }
    let mut lo = 0.0;
    let mut hi = 1.0;
    for _ in 0..40 {
        let mid = 0.5 * (lo + hi);
        if betai(alpha, beta, mid) < p {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    0.5 * (lo + hi)
}

fn betai(a: f64, b: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let log_bt = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let bt = if log_bt.is_finite() { log_bt.exp() } else { 0.0 };
    if x < (a + 1.0) / (a + b + 2.0) {
        bt * betacf(a, b, x) / a
    } else {
        1.0 - bt * betacf(b, a, 1.0 - x) / b
    }
}

/// Lanczos, g = 7. Enough for the model's Beta quantiles.
fn ln_gamma(z: f64) -> f64 {
    const P: [f64; 9] = [
        0.99999999999980993,
        676.5203681218851,
        -1259.1392167224028,
        771.32342877765313,
        -176.61502916214059,
        12.507343278686905,
        -0.13857109526572012,
        9.9843695780195716e-6,
        1.5056327351493116e-7,
    ];
    if z < 0.5 {
        let pi = std::f64::consts::PI;
        return (pi / (pi * z).sin()).ln() - ln_gamma(1.0 - z);
    }
    let z = z - 1.0;
    let mut acc = P[0];
    for (i, coeff) in P.iter().enumerate().skip(1) {
        acc += coeff / (z + i as f64);
    }
    let t = z + 7.5;
    (2.0 * std::f64::consts::PI).sqrt().ln() + (z + 0.5) * t.ln() - t + acc.ln()
}

fn betacf(a: f64, b: f64, x: f64) -> f64 {
    const MAX_IT: usize = 200;
    const EPS: f64 = 3.0e-12;
    const FPMIN: f64 = 1.0e-30;
    let qab = a + b;
    let qap = a + 1.0;
    let qam = a - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < FPMIN {
        d = FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=MAX_IT {
        let m = m as f64;
        let m2 = 2.0 * m;
        let mut aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < FPMIN {
            d = FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < FPMIN {
            c = FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < EPS {
            break;
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beta_quantiles_match_closed_form() {
        let cold = p_loss_hi(0, 0);
        let expected = 1.0 - 0.1_f64.powf(1.0 / 9.0);
        assert!((cold - expected).abs() < 1e-9);
        assert!((cold - 0.2257).abs() < 1e-3);

        let clean = p_loss_hi(0, 40);
        let expected_clean = 1.0 - 0.1_f64.powf(1.0 / 49.0);
        assert!((clean - expected_clean).abs() < 1e-9);
        assert!((clean - 0.0459).abs() < 1e-3);

        // α > 1 exercises the bisection, not the closed form.
        let with_loss = beta_quantile(2.0, 10.0, 0.90);
        assert!(with_loss > 0.0 && with_loss < 1.0);
        assert!((betai(2.0, 10.0, with_loss) - 0.90).abs() < 1e-6);
    }

    #[test]
    fn confidence_table() {
        let p = p_loss_hi(0, 0);
        let min = 0.95;

        let open = classify(1, 0, 0, p, min);
        assert_eq!(open.state, State::Open);
        assert_eq!(open.reason, Reason::Connected);
        assert!((open.confidence - 0.99).abs() < 1e-9);

        let closed = classify(0, 1, 0, p, min);
        assert_eq!(closed.state, State::Closed);
        assert!((closed.confidence - 0.97).abs() < 1e-9);

        let one = classify(0, 0, 1, p, min);
        assert_eq!(one.state, State::Uncertain);
        assert!((one.confidence - 0.813).abs() < 0.001);

        let two = classify(0, 0, 2, p, min);
        assert_eq!(two.state, State::Filtered);
        assert!((two.confidence - 0.9496).abs() < 0.001);

        let three = classify(0, 0, 3, p, min);
        assert_eq!(three.state, State::Filtered);
        assert!((three.confidence - 0.9879).abs() < 0.001);

        let p_clean = p_loss_hi(0, 40);
        let clean = classify(0, 0, 3, p_clean, min);
        assert_eq!(clean.state, State::Filtered);
        assert!(clean.confidence > 0.999);
    }

    #[test]
    fn mixed_evidence_stays_uncertain() {
        let p = p_loss_hi(0, 0);
        let v = classify(1, 1, 0, p, 0.95);
        assert_eq!(v.reason, Reason::Mixed);
        assert_eq!(v.state, State::Uncertain);
        assert!((v.confidence - 0.658).abs() < 0.02);
    }
}
