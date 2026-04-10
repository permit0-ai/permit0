#![forbid(unsafe_code)]

/// Configuration for a risk category used in the category-weighted base step.
#[derive(Debug, Clone)]
pub struct CategoryConfig {
    pub name: &'static str,
    pub flags: &'static [&'static str],
    pub amps: &'static [&'static str],
    pub weight: f64,
}

/// Per-flag base weights (fractions of 1.0).
/// NOT a probability distribution — multiple flags can fire simultaneously.
/// Calibration question: "if only this flag fired with no amplifiers,
/// what fraction of maximum risk does it represent?"
pub const BASE_RISK_WEIGHTS: &[(&str, f64)] = &[
    ("DESTRUCTION", 0.28),
    ("PHYSICAL", 0.26),
    ("EXECUTION", 0.22),
    ("PRIVILEGE", 0.20),
    ("FINANCIAL", 0.20),
    ("EXPOSURE", 0.16),
    ("GOVERNANCE", 0.14),
    ("OUTBOUND", 0.10),
    ("MUTATION", 0.10),
];

/// Amplifier weights — MUST sum to exactly 1.0.
/// Raising one entry requires lowering another.
pub const BASE_AMP_WEIGHTS: &[(&str, f64)] = &[
    ("destination", 0.155),
    ("sensitivity", 0.136),
    ("scope", 0.136),
    ("amount", 0.117),
    ("session", 0.097),
    ("irreversibility", 0.097),
    ("volume", 0.078),
    ("boundary", 0.078),
    ("actor", 0.058),
    ("environment", 0.048),
];

/// Raw integer ceilings — used only for normalisation.
pub const AMP_MAXES: &[(&str, i32)] = &[
    ("sensitivity", 35),
    ("scope", 35),
    ("boundary", 20),
    ("amount", 30),
    ("actor", 20),
    ("destination", 40),
    ("session", 30),
    ("volume", 25),
    ("irreversibility", 20),
    ("environment", 15),
];

/// Flag categories and their scorer weights.
pub const CATEGORIES: &[CategoryConfig] = &[
    CategoryConfig {
        name: "data",
        flags: &["OUTBOUND", "EXPOSURE", "MUTATION"],
        amps: &["sensitivity", "scope", "destination", "volume"],
        weight: 0.25,
    },
    CategoryConfig {
        name: "power",
        flags: &["DESTRUCTION", "PRIVILEGE", "FINANCIAL"],
        amps: &["amount", "irreversibility", "boundary", "environment"],
        weight: 0.35,
    },
    CategoryConfig {
        name: "control",
        flags: &["EXECUTION", "PHYSICAL", "GOVERNANCE"],
        amps: &["actor", "session", "scope", "environment"],
        weight: 0.40,
    },
];

/// Amplifier dimensions that participate in the multiplicative compound step.
pub const MULTIPLICATIVE_DIMS: &[&str] = &["irreversibility", "boundary", "destination"];

/// Default tanh squeeze constant.
pub const DEFAULT_TANH_K: f64 = 1.8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amp_weights_sum_to_one() {
        let sum: f64 = BASE_AMP_WEIGHTS.iter().map(|(_, w)| w).sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "AMP_WEIGHTS must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn category_weights_sum_to_one() {
        let sum: f64 = CATEGORIES.iter().map(|c| c.weight).sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "CATEGORIES weights must sum to 1.0, got {sum}"
        );
    }

    #[test]
    fn all_flags_in_exactly_one_category() {
        for &(flag, _) in BASE_RISK_WEIGHTS {
            let count = CATEGORIES
                .iter()
                .filter(|c| c.flags.contains(&flag))
                .count();
            assert_eq!(count, 1, "flag {flag} must appear in exactly one category");
        }
    }

    #[test]
    fn all_amp_dims_have_maxes() {
        for &(dim, _) in BASE_AMP_WEIGHTS {
            assert!(
                AMP_MAXES.iter().any(|(d, _)| *d == dim),
                "dim {dim} missing from AMP_MAXES"
            );
        }
    }
}
