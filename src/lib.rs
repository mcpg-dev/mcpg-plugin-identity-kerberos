//! `dev.mcpg.identity.kerberos` — Kerberos / SPNEGO (HTTP Negotiate) identity
//! plugin.
//!
//! Resolves caller identity from `Authorization: Negotiate <b64 GSSAPI token>`
//! by verifying the token against the gateway's service **keytab** with MIT
//! GSSAPI (`accept_sec_context`) and reading the caller's Kerberos principal.
//!
//! # Trust model
//!
//! A completed GSSAPI accept is cryptographic proof the caller holds a service
//! ticket the KDC issued to them, so `resolution.trust_level: "verified"`
//! (default) puts them in the same bucket as an OIDC-verified JWT.
//!
//! # Sync, no runtime
//!
//! GSSAPI accept is a synchronous, local cryptographic check (the keytab
//! decrypts the ticket — no call to the KDC), so unlike the oidc/ldap identity
//! plugins this carries no private tokio runtime.

pub mod config;
mod gss;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use mcpg_plugin_protocol::{
    IdentityProviderPlugin, IdentityResolution, PluginClass, PluginIdentity, PluginManifest,
};
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncIdentityResolver;
use serde_json::Value;
use tracing::{debug, info_span, warn};

pub use config::{ConfigError, KerberosConfig, ResolutionConfig};
use gss::GssResult;

const PLUGIN_ID: &str = "dev.mcpg.identity.kerberos";

fn record_resolve_outcome(result: &IdentityResolution, elapsed: std::time::Duration) {
    let outcome = match result {
        IdentityResolution::Resolved { .. } => "resolved",
        IdentityResolution::None => "none",
        IdentityResolution::Invalid { .. } => "invalid",
    };
    metrics::counter!("mcpg_identity_kerberos_resolutions_total", "outcome" => outcome)
        .increment(1);
    metrics::histogram!("mcpg_identity_kerberos_resolve_ms").record(elapsed.as_millis() as f64);
    match result {
        IdentityResolution::Resolved { identity } => debug!(
            subject = identity.subject_id.as_deref().unwrap_or(""),
            "kerberos identity resolved"
        ),
        IdentityResolution::None => debug!("kerberos identity: no Negotiate token — fall through"),
        IdentityResolution::Invalid { reason } => {
            warn!(reason = %reason, "kerberos identity: rejected")
        }
    }
}

pub struct KerberosIdentityPlugin {
    inner: Arc<Inner>,
}

struct Inner {
    manifest: PluginManifest,
    service_name: Option<String>,
    strip_realm: bool,
    resolution: ResolutionConfig,
}

impl KerberosIdentityPlugin {
    /// SDK macro factory: parse config + register the keytab. Panics on bad
    /// config — same stance as the oidc/basic siblings.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg = KerberosConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(plugin_id = PLUGIN_ID, error = %err, "kerberos identity: config parse failed; refusing to register");
            panic!(
                "kerberos identity config parse failed: {err}. A misconfigured \
                 identity resolver is a security hole; refusing to load."
            )
        });
        gss::register_keytab(&cfg.keytab).unwrap_or_else(|err| {
            panic!("kerberos identity: registering keytab failed: {err}");
        });
        tracing::info!(plugin_id = PLUGIN_ID, keytab = %cfg.keytab, "kerberos identity: keytab registered");
        Self {
            inner: Arc::new(Inner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "Kerberos / SPNEGO Identity Resolver".into(),
                    plugin_class: PluginClass::IdentityProvider,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities: Vec::new(),
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                service_name: cfg.service_name,
                strip_realm: cfg.strip_realm,
                resolution: cfg.resolution,
            }),
        }
    }

    fn build_identity(&self, principal: String) -> PluginIdentity {
        let inner = &self.inner;
        let (user, realm) = gss::split_principal(&principal);
        let subject = if inner.strip_realm {
            user
        } else {
            principal.clone()
        };
        let mut attributes = BTreeMap::new();
        attributes.insert("principal".to_owned(), principal);
        if let Some(r) = &realm {
            attributes.insert("realm".to_owned(), r.clone());
        }
        PluginIdentity {
            kind: inner.resolution.trust_level.clone(),
            trust_level: inner.resolution.trust_level.clone(),
            subject_id: Some(subject),
            auth_provider: Some(inner.resolution.auth_provider_label.clone()),
            issuer: realm.map(|r| format!("krb5:{r}")),
            roles: Vec::new(),
            groups: Vec::new(),
            scopes: Vec::new(),
            attributes,
        }
    }

    /// Core resolve — synchronous GSSAPI accept.
    fn resolve(&self, headers: &[(String, String)]) -> IdentityResolution {
        let Some(auth) = lookup_header(headers, "authorization") else {
            return IdentityResolution::None;
        };
        let Some(token_b64) = strip_negotiate_prefix(auth) else {
            return IdentityResolution::None;
        };
        if token_b64.is_empty() {
            return IdentityResolution::None;
        }
        let token = match BASE64_STANDARD.decode(token_b64.as_bytes()) {
            Ok(t) => t,
            Err(_) => {
                return IdentityResolution::Invalid {
                    reason: "malformed Negotiate token (base64)".into(),
                };
            }
        };
        match gss::accept(self.inner.service_name.as_deref(), &token) {
            GssResult::Authenticated(principal) => IdentityResolution::Resolved {
                identity: self.build_identity(principal),
            },
            GssResult::BadToken(detail) => {
                warn!(detail = %detail, "kerberos identity: token rejected");
                IdentityResolution::Invalid {
                    reason: "invalid or expired Kerberos token".into(),
                }
            }
            GssResult::Continuation => IdentityResolution::Invalid {
                reason: "multi-leg negotiation is not supported".into(),
            },
            GssResult::ServerError(detail) => {
                // Fail closed: an acceptor-side problem (keytab) rejects rather
                // than passing through.
                warn!(detail = %detail, "kerberos identity: acceptor error; failing closed");
                IdentityResolution::Invalid {
                    reason: "kerberos acceptor unavailable".into(),
                }
            }
        }
    }
}

fn lookup_header<'a>(headers: &'a [(String, String)], target: &str) -> Option<&'a str> {
    headers
        .iter()
        .find_map(|(name, value)| name.eq_ignore_ascii_case(target).then_some(value.as_str()))
}

/// Strip a case-insensitive `Negotiate ` scheme prefix (RFC 4559).
fn strip_negotiate_prefix(value: &str) -> Option<&str> {
    let scheme: String = value.chars().take(9).collect();
    if scheme.len() != 9 || !scheme.eq_ignore_ascii_case("Negotiate") {
        return None;
    }
    value[9..].strip_prefix(' ')
}

#[async_trait]
impl IdentityProviderPlugin for KerberosIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    async fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_kerberos_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = self.resolve(headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

impl SyncIdentityResolver for KerberosIdentityPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn resolve_identity(
        &self,
        headers: &[(String, String)],
        _metadata: &mcpg_plugin_protocol::types::RequestMetadata,
        _config: &Value,
    ) -> IdentityResolution {
        let _span = info_span!("identity_kerberos_resolve", plugin_id = PLUGIN_ID).entered();
        let started = std::time::Instant::now();
        let result = self.resolve(headers);
        record_resolve_outcome(&result, started.elapsed());
        result
    }
}

declare_plugin! {

    plugin_id: "dev.mcpg.identity.kerberos",
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    // accept_sec_context is a local keytab check — no outbound network.
    capabilities: &[],
    entities: [
        identity as id {
            inner_name: "",
            plugin_type: KerberosIdentityPlugin,
            factory: |cfg: &str, _host: ::mcpg_plugin_sdk::HostHandle| -> KerberosIdentityPlugin {
                KerberosIdentityPlugin::from_config_json(cfg)
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plugin() -> KerberosIdentityPlugin {
        // `keytab` must exist for config validation — point at this source.
        KerberosIdentityPlugin::from_config_json(
            &json!({ "keytab": concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml") }).to_string(),
        )
    }

    fn negotiate(token_b64: &str) -> Vec<(String, String)> {
        vec![("Authorization".into(), format!("Negotiate {token_b64}"))]
    }

    #[test]
    fn no_authorization_header_is_none() {
        assert!(matches!(plugin().resolve(&[]), IdentityResolution::None));
    }

    #[test]
    fn basic_scheme_is_none() {
        let h = vec![("Authorization".into(), "Basic abc".into())];
        assert!(matches!(plugin().resolve(&h), IdentityResolution::None));
    }

    #[test]
    fn malformed_base64_is_invalid() {
        match plugin().resolve(&negotiate("!!not base64!!")) {
            IdentityResolution::Invalid { reason } => assert!(reason.contains("base64")),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn garbage_token_is_invalid() {
        // Well-formed base64 but a bogus GSSAPI token → accept rejects → a
        // generic (no-detail) rejection.
        let bogus = BASE64_STANDARD.encode(b"not a real gssapi token");
        match plugin().resolve(&negotiate(&bogus)) {
            IdentityResolution::Invalid { reason } => assert!(
                reason == "invalid or expired Kerberos token"
                    || reason == "kerberos acceptor unavailable"
            ),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn manifest_is_identity_provider() {
        let p = plugin();
        let m = SyncIdentityResolver::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::IdentityProvider);
    }
}
