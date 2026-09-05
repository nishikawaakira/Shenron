//! The curated Sigma rule pack shipped with Shenron.
//!
//! These rules are embedded at compile time, so `shenron setup` can install
//! a set of Shenron-supported generic-TTP rules into the local data directory
//! regardless of where the binary runs — no network access is needed for the
//! bundled pack. Each rule stays within the intentionally small supported Sigma
//! subset and never asserts an attack, exploitation, compromise, or a vulnerable
//! product.

use std::{fs, path::Path};

use anyhow::{Context, Result};

/// `(filename, YAML contents)` for every bundled rule, embedded at compile time.
pub const BUNDLED_RULES: &[(&str, &str)] = &[
    (
        "secret-and-config-file-probe.yml",
        include_str!("../sigma-rules/secret-and-config-file-probe.yml"),
    ),
    (
        "version-control-exposure-probe.yml",
        include_str!("../sigma-rules/version-control-exposure-probe.yml"),
    ),
    (
        "admin-and-actuator-endpoint-probe.yml",
        include_str!("../sigma-rules/admin-and-actuator-endpoint-probe.yml"),
    ),
];

/// Directory name the bundled pack is installed under, inside the Sigma rules
/// directory. Fetched external rules are kept in sibling directories so the two
/// sources stay distinguishable.
pub const BUNDLED_PACK_DIR: &str = "shenron-pack";

/// Install the bundled pack into `<sigma_rules_dir>/shenron-pack/`, overwriting
/// only the pack's own files. Returns the number of rules written.
pub fn install_bundled_pack(sigma_rules_dir: &Path) -> Result<usize> {
    let pack_dir = sigma_rules_dir.join(BUNDLED_PACK_DIR);
    fs::create_dir_all(&pack_dir)
        .with_context(|| format!("creating Sigma pack directory {}", pack_dir.display()))?;
    for (name, body) in BUNDLED_RULES {
        let path = pack_dir.join(name);
        fs::write(&path, body).with_context(|| format!("writing Sigma rule {}", path.display()))?;
    }
    Ok(BUNDLED_RULES.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::load_rules;
    use tempfile::tempdir;

    #[test]
    fn every_bundled_rule_is_in_the_supported_subset() {
        let dir = tempdir().unwrap();
        let written = install_bundled_pack(dir.path()).unwrap();
        assert_eq!(written, BUNDLED_RULES.len());
        let ruleset = load_rules(dir.path());
        // All bundled rules load as supported; none is skipped.
        assert_eq!(ruleset.supported.len(), BUNDLED_RULES.len());
        assert!(ruleset.unsupported.is_empty());
    }

    // Regression: `/.well-known/security.txt` is the RFC 9116 standard path that
    // well-behaved crawlers and researchers request; it is not a probe indicator
    // and must not be flagged by any bundled rule. See commit that removed it
    // from the management/actuator probe.
    #[test]
    fn bundled_pack_does_not_flag_the_standard_security_txt_path() {
        let dir = tempdir().unwrap();
        install_bundled_pack(dir.path()).unwrap();
        let ruleset = load_rules(dir.path());
        let matches_any = |path: &str| {
            let event = crate::access_log::parse_combined_line(
                &format!(
                    r#"203.0.113.9 - - [17/Aug/2026:00:00:00 +0900] "GET {path} HTTP/1.1" 200 12 "-" "curl/8""#
                ),
                crate::access_log::AccessLogFormat::ApacheCombined,
            )
            .unwrap();
            ruleset.supported.iter().any(|rule| rule.matches(&event))
        };

        // The standard well-known path (and an ordinary page) are not flagged.
        assert!(!matches_any("/.well-known/security.txt"));
        assert!(!matches_any("/index.html"));

        // Genuine probe paths are still flagged, so the rule was narrowed, not
        // disabled.
        assert!(matches_any("/.env"));
        assert!(matches_any("/.git/config"));
        assert!(matches_any("/actuator/health"));
    }
}
