//! Stable local locations for public, reproducible Shenron inputs.
//!
//! These paths are used only to locate local files. Resolving them never
//! creates directories or accesses the network.

use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Default local data directory for public, prepared threat-intelligence
/// inputs. The precedence is `SHENRON_DATA_DIR`, `XDG_DATA_HOME/shenron`, then
/// `$HOME/.local/share/shenron`.
pub fn default_data_dir() -> PathBuf {
    data_dir_from_environment(
        env::var_os("SHENRON_DATA_DIR"),
        env::var_os("XDG_DATA_HOME"),
        env::var_os("HOME"),
    )
}

/// Default local Nuclei checkout created by `shenron-lab nuclei update`.
pub fn default_templates_dir() -> PathBuf {
    default_data_dir().join("nuclei-templates")
}

/// Default frozen Nuclei report created by `shenron-lab nuclei update`.
pub fn default_nuclei_report() -> PathBuf {
    default_data_dir().join("nuclei-report.json")
}

/// Default downloaded CISA KEV catalog created by `shenron-lab setup`.
pub fn default_kev_snapshot() -> PathBuf {
    default_data_dir().join("known_exploited_vulnerabilities.json")
}

/// Default frozen KEV/Nuclei join report created by `shenron-lab setup`.
pub fn default_kev_report() -> PathBuf {
    default_data_dir().join("kev-report.json")
}

/// Default local reputation dataset created by `shenron-lab reputation update`.
pub fn default_reputation_dataset() -> PathBuf {
    default_data_dir().join("reputation.jsonl")
}

/// Default local IPv4 ASN-range dataset created by `shenron-lab reputation update`.
pub fn default_asn_dataset() -> PathBuf {
    default_data_dir().join("asn-ranges.tsv")
}

/// Default frozen published crawler-range snapshot created by
/// `shenron-lab bot-ranges update` or `shenron-lab setup`.
pub fn default_bot_range_snapshot() -> PathBuf {
    default_data_dir().join("bot-ranges.json")
}

/// Default local Sigma rules directory for the `production hunt` Sigma pass.
pub fn default_sigma_rules_dir() -> PathBuf {
    default_data_dir().join("sigma-rules")
}

fn data_dir_from_environment(
    shenron_data_dir: Option<OsString>,
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> PathBuf {
    if let Some(path) = nonempty_path(shenron_data_dir) {
        return path;
    }
    if let Some(path) = nonempty_path(xdg_data_home) {
        return path.join("shenron");
    }
    if let Some(path) = nonempty_path(home) {
        return path.join(".local/share/shenron");
    }
    // `HOME` is expected on supported Unix systems. Keep the helper total for
    // unusual minimal environments without inventing a networked fallback.
    Path::new(".local/share/shenron").to_owned()
}

fn nonempty_path(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_data_directory_with_shenron_override_first() {
        assert_eq!(
            data_dir_from_environment(
                Some(OsString::from("/tmp/shenron-data")),
                Some(OsString::from("/tmp/xdg")),
                Some(OsString::from("/tmp/home")),
            ),
            PathBuf::from("/tmp/shenron-data")
        );
    }

    #[test]
    fn resolves_data_directory_from_xdg_then_home() {
        assert_eq!(
            data_dir_from_environment(
                None,
                Some(OsString::from("/tmp/xdg")),
                Some(OsString::from("/tmp/home")),
            ),
            PathBuf::from("/tmp/xdg/shenron")
        );
        assert_eq!(
            data_dir_from_environment(None, None, Some(OsString::from("/tmp/home"))),
            PathBuf::from("/tmp/home/.local/share/shenron")
        );
    }
}
