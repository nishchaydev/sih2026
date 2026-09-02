#![allow(dead_code)]

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub enum EntropyVerdict {
    Pass,
    Warning,
    Fail,
}

impl std::fmt::Display for EntropyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Warning => write!(f, "WARNING"),
            Self::Fail => write!(f, "FAIL"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyResult {
    pub shannon_entropy: f64,
    pub chi_square: f64,
    pub verdict: EntropyVerdict,
    pub expected_entropy: f64,
    pub description: String,
}

/// Calculate Shannon entropy of a data buffer.
/// Returns bits per byte: 0.0 = all identical, 8.0 = perfect random.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Calculate chi-square statistic for uniformity test.
/// For truly random data with 256 possible values, expected frequency = N/256.
pub fn chi_square(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let expected = data.len() as f64 / 256.0;
    let mut chi2 = 0.0f64;

    for &count in &freq {
        let diff = count as f64 - expected;
        chi2 += (diff * diff) / expected;
    }

    chi2
}

/// Analyze a data buffer and determine if it matches the expected erasure pattern.
/// For zero-fill: expects entropy ≈ 0.0
/// For random-fill: expects entropy ≈ 8.0
pub fn analyze(data: &[u8], is_random_method: bool) -> EntropyResult {
    let h = shannon_entropy(data);
    let chi2 = chi_square(data);

    if is_random_method {
        let verdict = if h >= 7.99 {
            EntropyVerdict::Pass
        } else if h >= 7.90 {
            EntropyVerdict::Warning
        } else {
            EntropyVerdict::Fail
        };

        EntropyResult {
            shannon_entropy: h,
            chi_square: chi2,
            verdict,
            expected_entropy: 8.0,
            description: format!(
                "Entropy: {:.4} bits/byte (expected ≈ 8.0 for random). Chi²: {:.2}",
                h, chi2
            ),
        }
    } else {
        // For fixed-pattern methods (zero, 0xFF, etc.), entropy should be very low
        let verdict = if h < 0.01 {
            EntropyVerdict::Pass
        } else if h < 0.5 {
            EntropyVerdict::Warning
        } else {
            EntropyVerdict::Fail
        };

        EntropyResult {
            shannon_entropy: h,
            chi_square: chi2,
            verdict,
            expected_entropy: 0.0,
            description: format!(
                "Entropy: {:.4} bits/byte (expected ≈ 0.0 for fixed pattern). Chi²: {:.2}",
                h, chi2
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_entropy() {
        let zeros = vec![0u8; 10000];
        assert_eq!(shannon_entropy(&zeros), 0.0);
        let res = analyze(&zeros, false);
        assert!(matches!(res.verdict, EntropyVerdict::Pass));
    }

    #[test]
    fn test_random_entropy() {
        use rand::RngCore;
        let mut data = vec![0u8; 65536];
        rand::thread_rng().fill_bytes(&mut data);
        let h = shannon_entropy(&data);
        assert!(h > 7.95, "Expected high entropy for random data, got {}", h);
        let res = analyze(&data, true);
        assert!(matches!(res.verdict, EntropyVerdict::Pass | EntropyVerdict::Warning));
    }
}

