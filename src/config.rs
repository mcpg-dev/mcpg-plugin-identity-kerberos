//! Operator-supplied configuration schema for `dev.mcpg.identity.kerberos`.

use serde::Deserialize;
use thiserror::Error;

/// Top-level plugin config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KerberosConfig {
    /// Path to the service **keytab** holding the gateway's service
    /// principal key(s). Registered as the GSSAPI acceptor identity. A
    /// `${env.X}` / `vault://…` / `file://…` reference is resolved by the
    /// gateway secret-resolver to a path before it reaches the plugin.
    pub keytab: String,

    /// Optional hostbased service name to acquire the acceptor credential for
    /// (e.g. `HTTP/gateway.corp.example.com`). Omit to accept any principal
    /// present in the keytab.
    #[serde(default)]
    pub service_name: Option<String>,

    /// Use the principal's local part (before `@REALM`) as `subject_id`
    /// (`alice@CORP.EXAMPLE.COM` → `alice`). The full principal is always kept
    /// in `attributes.principal`. Default `true`.
    #[serde(default = "default_true")]
    pub strip_realm: bool,

    /// Trust level + provider label applied to resolved identities.
    #[serde(default)]
    pub resolution: ResolutionConfig,
}

/// Trust posture applied to authenticated callers.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionConfig {
    /// A completed GSSAPI accept cryptographically proves the caller holds a
    /// service ticket the KDC issued for them, so `"verified"` is the natural
    /// default; operators on weaker contracts downgrade to
    /// `"header_asserted"`.
    #[serde(default = "default_trust_level")]
    pub trust_level: String,
    /// `auth_provider` label on the resolved `PluginIdentity`.
    #[serde(default = "default_auth_provider_label")]
    pub auth_provider_label: String,
}

impl Default for ResolutionConfig {
    fn default() -> Self {
        Self {
            trust_level: default_trust_level(),
            auth_provider_label: default_auth_provider_label(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_trust_level() -> String {
    "verified".into()
}
fn default_auth_provider_label() -> String {
    "kerberos".into()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid identity.kerberos config JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("identity.kerberos: keytab must not be empty")]
    EmptyKeytab,
    #[error("identity.kerberos: keytab file not found: {0}")]
    KeytabNotFound(String),
    #[error("identity.kerberos: invalid trust_level `{0}` (allowed: verified | header_asserted)")]
    InvalidTrustLevel(String),
}

impl KerberosConfig {
    /// Parse + validate from JSON.
    pub fn parse(s: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.keytab.trim().is_empty() {
            return Err(ConfigError::EmptyKeytab);
        }
        if !std::path::Path::new(&self.keytab).exists() {
            return Err(ConfigError::KeytabNotFound(self.keytab.clone()));
        }
        match self.resolution.trust_level.as_str() {
            "verified" | "header_asserted" => {}
            other => return Err(ConfigError::InvalidTrustLevel(other.into())),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_missing_keytab_file() {
        let cfg = json!({ "keytab": "/no/such/keytab" }).to_string();
        let err = KerberosConfig::parse(&cfg).unwrap_err();
        assert!(matches!(err, ConfigError::KeytabNotFound(_)));
    }

    #[test]
    fn rejects_empty_keytab() {
        let cfg = json!({ "keytab": "  " }).to_string();
        assert!(matches!(
            KerberosConfig::parse(&cfg).unwrap_err(),
            ConfigError::EmptyKeytab
        ));
    }

    /// A real on-disk stand-in for the keytab existence check — the
    /// test writes it, so it exists in any sandbox the test runs in.
    fn keytab_stand_in() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("mcpg-kerberos-test-keytab-{}", std::process::id()));
        std::fs::write(&path, b"stand-in").expect("write keytab stand-in");
        path
    }

    #[test]
    fn parses_with_existing_keytab() {
        let here = keytab_stand_in();
        let cfg = json!({ "keytab": here, "service_name": "HTTP/gw.example.com" }).to_string();
        let parsed = KerberosConfig::parse(&cfg).unwrap();
        assert!(parsed.strip_realm);
        assert_eq!(parsed.resolution.trust_level, "verified");
        assert_eq!(parsed.service_name.as_deref(), Some("HTTP/gw.example.com"));
    }

    #[test]
    fn rejects_bad_trust_level() {
        let cfg = json!({ "keytab": keytab_stand_in(), "resolution": { "trust_level": "alien" } })
            .to_string();
        assert!(matches!(
            KerberosConfig::parse(&cfg).unwrap_err(),
            ConfigError::InvalidTrustLevel(_)
        ));
    }
}
