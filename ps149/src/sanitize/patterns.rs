use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub enum SanitizeMethod {
    /// Fast wipe — headers & footers only (16 MB each end)
    FastWipe,
    /// NIST SP 800-88 Clear — single pass zero fill
    NistClear,
    /// NIST SP 800-88 Purge — single pass random
    NistPurge,
    /// DoD 5220.22-M (E) — 3 passes: 0x00, 0xFF, Random
    Dod3Pass,
    /// DoD 5220.22-M (ECE) — 7 passes
    Dod7Pass,
    /// Peter Gutmann — 35 passes
    Gutmann,
    /// RCMP TSSIT OPS-II — 7 passes (Canadian)
    RcmpTssit,
    /// HMG IS5 Baseline — 1 pass 0x00 (UK)
    HmgIs5Baseline,
    /// HMG IS5 Enhanced — 3 passes (UK)
    HmgIs5Enhanced,
    /// VSITR — 7 passes (German BSI)
    Vsitr,
    /// Bruce Schneier — 7 passes
    Schneier,
    /// AFSSI-5020 — 3 passes (US Air Force)
    Afssi5020,
    /// AR 380-19 — 3 passes (US Army)
    Ar38019,
    /// NAVSO P-5239-26 — 3 passes (US Navy)
    NavsoP523926,
    /// Single pass cryptographic random
    Random1Pass,
    /// GOST R 50739-95 — 2 passes (Russian)
    GostR50739,
    /// Smart Secure — critical zones + boundary breaks (~1 min)
    SmartSecure,
    /// Hardware crypto-erase via IOCTL_STORAGE_REINITIALIZE_MEDIA — internal
    /// NVMe only. Deliberately excluded from `all_methods()`: it's not a
    /// pattern-overwrite method (no passes, no `FillPattern`), so it never
    /// appears in the numbered method menu and is never routed through
    /// `sanitize::execute_sanitization`/`get_pattern` below. It exists as a
    /// variant purely so `sanitize::hardware_erase`'s result can reuse the
    /// existing `SanitizationCertificate::build()` plumbing unchanged — see
    /// `sanitize::hardware_erase` for the actual execution path.
    NvmeCryptoErase,
}

impl SanitizeMethod {
    pub fn pass_count(&self) -> usize {
        match self {
            Self::FastWipe | Self::SmartSecure | Self::NistClear | Self::HmgIs5Baseline | Self::Random1Pass => 1,
            Self::NistPurge | Self::GostR50739 => 2,
            Self::Dod3Pass | Self::HmgIs5Enhanced | Self::Afssi5020 | Self::Ar38019 | Self::NavsoP523926 => 3,
            Self::Dod7Pass | Self::RcmpTssit | Self::Vsitr | Self::Schneier => 7,
            Self::Gutmann => 35,
            Self::NvmeCryptoErase => 1,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::FastWipe => "Fast Wipe (Headers & Footers)",
            Self::NistClear => "NIST 800-88 Clear (Zero Fill)",
            Self::NistPurge => "NIST 800-88 Purge (Random)",
            Self::Dod3Pass => "DoD 5220.22-M (3-Pass)",
            Self::Dod7Pass => "DoD 5220.22-M ECE (7-Pass)",
            Self::Gutmann => "Gutmann (35-Pass)",
            Self::RcmpTssit => "RCMP TSSIT OPS-II (7-Pass)",
            Self::HmgIs5Baseline => "HMG IS5 Baseline (1-Pass)",
            Self::HmgIs5Enhanced => "HMG IS5 Enhanced (3-Pass)",
            Self::Vsitr => "VSITR (7-Pass)",
            Self::Schneier => "Bruce Schneier (7-Pass)",
            Self::Afssi5020 => "AFSSI-5020 (3-Pass)",
            Self::Ar38019 => "AR 380-19 (3-Pass)",
            Self::NavsoP523926 => "NAVSO P-5239-26 (3-Pass)",
            Self::Random1Pass => "Random Single Pass",
            Self::GostR50739 => "GOST R 50739-95 (2-Pass)",
            Self::SmartSecure => "Smart Secure Wipe (~1 min)",
            Self::NvmeCryptoErase => "Hardware Fast Erase (NVMe Crypto Erase)",
        }
    }

    pub fn standard_name(&self) -> &'static str {
        match self {
            Self::FastWipe => "Non-Standard (Header Wipe)",
            Self::NistClear => "NIST SP 800-88 Clear",
            Self::NistPurge => "NIST SP 800-88 Purge",
            Self::Dod3Pass => "DoD 5220.22-M (E)",
            Self::Dod7Pass => "DoD 5220.22-M (ECE)",
            Self::Gutmann => "Gutmann 1996",
            Self::RcmpTssit => "RCMP TSSIT OPS-II",
            Self::HmgIs5Baseline => "HMG IS5 Baseline",
            Self::HmgIs5Enhanced => "HMG IS5 Enhanced",
            Self::Vsitr => "VSITR (German BSI)",
            Self::Schneier => "Schneier Method",
            Self::Afssi5020 => "AFSSI-5020 (USAF)",
            Self::Ar38019 => "AR 380-19 (US Army)",
            Self::NavsoP523926 => "NAVSO P-5239-26 (USN)",
            Self::Random1Pass => "Academic Consensus",
            Self::GostR50739 => "GOST R 50739-95 (Russia)",
            Self::SmartSecure => "PS-26149 Innovation (Zone-Based)",
            Self::NvmeCryptoErase => "NIST SP 800-88 Purge (Hardware Crypto Erase)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::FastWipe => "Destroys partition tables only — fastest option",
            Self::NistClear => "Single pass of zeros — US government standard",
            Self::NistPurge => "Random overwrite + verify — higher assurance",
            Self::Dod3Pass => "US Department of Defense short method",
            Self::Dod7Pass => "US Department of Defense extended method",
            Self::Gutmann => "35-pass legacy method for old MFM/RLL drives",
            Self::RcmpTssit => "Canadian Royal Mounted Police standard",
            Self::HmgIs5Baseline => "UK Government baseline — single zero pass",
            Self::HmgIs5Enhanced => "UK Government enhanced — 3 passes",
            Self::Vsitr => "German Federal Office (BSI) standard",
            Self::Schneier => "Bruce Schneier's 7-pass method",
            Self::Afssi5020 => "US Air Force standard",
            Self::Ar38019 => "US Army regulation standard",
            Self::NavsoP523926 => "US Navy standard",
            Self::Random1Pass => "Single pass CSPRNG — modern academic consensus",
            Self::GostR50739 => "Russian Federal data protection standard",
            Self::SmartSecure => "Zones: metadata + boundaries — fast & unrecoverable",
            Self::NvmeCryptoErase => "Drive controller resets its encryption key — seconds, internal NVMe only",
        }
    }

    /// Returns all methods in menu display order.
    pub fn all_methods() -> &'static [SanitizeMethod] {
        &[
            Self::FastWipe,
            Self::SmartSecure,
            Self::NistClear,
            Self::NistPurge,
            Self::Random1Pass,
            Self::Dod3Pass,
            Self::Dod7Pass,
            Self::Afssi5020,
            Self::Ar38019,
            Self::NavsoP523926,
            Self::HmgIs5Baseline,
            Self::HmgIs5Enhanced,
            Self::Vsitr,
            Self::RcmpTssit,
            Self::Schneier,
            Self::GostR50739,
            Self::Gutmann,
        ]
    }
}

#[derive(Debug, Clone)]
pub enum FillPattern {
    Fixed(u8),
    Random,
    ThreeByteRepeating(u8, u8, u8),
}

pub fn get_pattern(pass_index: usize, method: SanitizeMethod) -> FillPattern {
    match method {
        SanitizeMethod::FastWipe | SanitizeMethod::SmartSecure | SanitizeMethod::NistClear | SanitizeMethod::HmgIs5Baseline => {
            FillPattern::Fixed(0x00)
        }
        SanitizeMethod::NistPurge => match pass_index {
            0 => FillPattern::Random,
            _ => FillPattern::Fixed(0x00), // verify pass
        },
        SanitizeMethod::Random1Pass => FillPattern::Random,
        SanitizeMethod::Dod3Pass | SanitizeMethod::HmgIs5Enhanced | SanitizeMethod::Afssi5020 => {
            match pass_index {
                0 => FillPattern::Fixed(0x00),
                1 => FillPattern::Fixed(0xFF),
                _ => FillPattern::Random,
            }
        }
        SanitizeMethod::Ar38019 => match pass_index {
            0 => FillPattern::Random,
            1 => FillPattern::Fixed(0x00),
            _ => FillPattern::Fixed(0xFF),
        },
        SanitizeMethod::NavsoP523926 => match pass_index {
            0 => FillPattern::Fixed(0x01),
            1 => FillPattern::Fixed(0xFE),
            _ => FillPattern::Random,
        },
        SanitizeMethod::GostR50739 => match pass_index {
            0 => FillPattern::Fixed(0x00),
            _ => FillPattern::Random,
        },
        SanitizeMethod::Dod7Pass => match pass_index {
            0 => FillPattern::Fixed(0x55),
            1 => FillPattern::Fixed(0xAA),
            2 => FillPattern::Random,
            3 => FillPattern::Fixed(0x96),
            4 => FillPattern::Fixed(0x00),
            5 => FillPattern::Fixed(0xFF),
            _ => FillPattern::Random,
        },
        SanitizeMethod::RcmpTssit => match pass_index {
            0 | 2 | 4 => FillPattern::Fixed(0x00),
            1 | 3 | 5 => FillPattern::Fixed(0xFF),
            _ => FillPattern::Random,
        },
        SanitizeMethod::Vsitr => match pass_index {
            0 | 2 | 4 => FillPattern::Fixed(0x00),
            1 | 3 | 5 => FillPattern::Fixed(0xFF),
            _ => FillPattern::Fixed(0xAA),
        },
        SanitizeMethod::Schneier => match pass_index {
            0 => FillPattern::Fixed(0xFF),
            1 => FillPattern::Fixed(0x00),
            _ => FillPattern::Random,
        },
        SanitizeMethod::Gutmann => match pass_index {
            // Passes 1-4: Random
            0..=3 => FillPattern::Random,
            // Pass 5: 0x55
            4 => FillPattern::Fixed(0x55),
            // Pass 6: 0xAA
            5 => FillPattern::Fixed(0xAA),
            // Passes 7-9: 3-byte repeating patterns (MFM encoding)
            6 => FillPattern::ThreeByteRepeating(0x92, 0x49, 0x24),
            7 => FillPattern::ThreeByteRepeating(0x49, 0x24, 0x92),
            8 => FillPattern::ThreeByteRepeating(0x24, 0x92, 0x49),
            // Passes 10-25: Fixed single bytes 0x00 through 0xFF
            9 => FillPattern::Fixed(0x00),
            10 => FillPattern::Fixed(0x11),
            11 => FillPattern::Fixed(0x22),
            12 => FillPattern::Fixed(0x33),
            13 => FillPattern::Fixed(0x44),
            14 => FillPattern::Fixed(0x55),
            15 => FillPattern::Fixed(0x66),
            16 => FillPattern::Fixed(0x77),
            17 => FillPattern::Fixed(0x88),
            18 => FillPattern::Fixed(0x99),
            19 => FillPattern::Fixed(0xAA),
            20 => FillPattern::Fixed(0xBB),
            21 => FillPattern::Fixed(0xCC),
            22 => FillPattern::Fixed(0xDD),
            23 => FillPattern::Fixed(0xEE),
            24 => FillPattern::Fixed(0xFF),
            // Passes 26-28: 3-byte repeating (RLL encoding)
            25 => FillPattern::ThreeByteRepeating(0x92, 0x49, 0x24),
            26 => FillPattern::ThreeByteRepeating(0x49, 0x24, 0x92),
            27 => FillPattern::ThreeByteRepeating(0x24, 0x92, 0x49),
            // Passes 29-31: 3-byte repeating
            28 => FillPattern::ThreeByteRepeating(0x6D, 0xB6, 0xDB),
            29 => FillPattern::ThreeByteRepeating(0xB6, 0xDB, 0x6D),
            30 => FillPattern::ThreeByteRepeating(0xDB, 0x6D, 0xB6),
            // Passes 32-35: Random
            _ => FillPattern::Random,
        },
        // Never actually invoked — NvmeCryptoErase bypasses the pattern-write
        // pipeline entirely (see `sanitize::hardware_erase`). Arm exists only
        // because `SanitizeMethod` match statements must stay exhaustive.
        SanitizeMethod::NvmeCryptoErase => FillPattern::Fixed(0x00),
    }
}

/// Fill a buffer with the specified pattern.
pub fn fill_buffer(buf: &mut [u8], pattern: &FillPattern) {
    match pattern {
        FillPattern::Fixed(val) => {
            buf.fill(*val);
        }
        FillPattern::Random => {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(buf);
        }
        FillPattern::ThreeByteRepeating(a, b, c) => {
            let pattern = [*a, *b, *c];
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = pattern[i % 3];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_methods_pass_count() {
        for method in SanitizeMethod::all_methods() {
            assert!(method.pass_count() >= 1);
            assert!(!method.display_name().is_empty());
            assert!(!method.standard_name().is_empty());
            assert!(!method.description().is_empty());
            for p in 0..method.pass_count() {
                let _pattern = get_pattern(p, *method);
            }
        }
    }

    #[test]
    fn test_fill_fixed() {
        let mut buf = vec![0u8; 1024];
        fill_buffer(&mut buf, &FillPattern::Fixed(0xAA));
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn test_fill_three_byte_repeating() {
        let mut buf = vec![0u8; 6];
        fill_buffer(&mut buf, &FillPattern::ThreeByteRepeating(0x12, 0x34, 0x56));
        assert_eq!(buf, vec![0x12, 0x34, 0x56, 0x12, 0x34, 0x56]);
    }
}

