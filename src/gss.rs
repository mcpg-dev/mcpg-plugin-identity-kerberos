//! GSSAPI server-side accept (synchronous MIT GSSAPI via libgssapi).
//!
//! `accept_sec_context` verifies the caller's SPNEGO/Kerberos token against
//! the registered service keytab — a purely local cryptographic check (the
//! KDC is contacted by the *client* to obtain the service ticket, not here),
//! so there is no outbound network.

use std::ffi::CString;

use libgssapi::context::{SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

// MIT krb5 GSSAPI extension: select the keytab used as the acceptor identity.
// Linked via libgssapi (which links libgssapi_krb5). Process-global — the
// gateway uses one service keytab.
unsafe extern "C" {
    fn krb5_gss_register_acceptor_identity(identity: *const std::os::raw::c_char) -> u32;
}

/// Register the service keytab as the GSSAPI acceptor identity. Called once at
/// plugin construction.
pub fn register_keytab(path: &str) -> Result<(), String> {
    let c = CString::new(path).map_err(|e| format!("keytab path has interior NUL: {e}"))?;
    // SAFETY: `c` is a valid NUL-terminated C string that outlives the call.
    let major = unsafe { krb5_gss_register_acceptor_identity(c.as_ptr()) };
    if major != 0 {
        return Err(format!(
            "krb5_gss_register_acceptor_identity('{path}') failed (major=0x{major:08x})"
        ));
    }
    Ok(())
}

/// Outcome of an accept attempt.
pub enum GssResult {
    /// Context established — the caller's Kerberos principal.
    Authenticated(String),
    /// The token was rejected (bad/expired ticket, wrong service, replay).
    BadToken(String),
    /// The mechanism needs more than one leg — unsupported for a stateless
    /// per-request resolver.
    Continuation,
    /// Acceptor-side problem (keytab/credential) — an operator misconfig.
    ServerError(String),
}

fn acquire_acceptor_cred(service_name: Option<&str>) -> Result<Cred, String> {
    let name = match service_name {
        Some(s) => {
            let n = Name::new(s.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
                .map_err(|e| format!("service name '{s}': {e}"))?;
            let canon = n
                .canonicalize(Some(GSS_MECH_KRB5))
                .map_err(|e| format!("canonicalize service name '{s}': {e}"))?;
            Some(canon)
        }
        None => None,
    };
    // `desired_mechs = None` → accept any mechanism the keytab supports
    // (SPNEGO + raw Kerberos), which is what HTTP Negotiate clients send.
    Cred::acquire(name.as_ref(), None, CredUsage::Accept, None)
        .map_err(|e| format!("acquire acceptor credential from keytab: {e}"))
}

/// Verify one GSSAPI token against the registered keytab.
pub fn accept(service_name: Option<&str>, token: &[u8]) -> GssResult {
    let cred = match acquire_acceptor_cred(service_name) {
        Ok(c) => c,
        Err(e) => return GssResult::ServerError(e),
    };
    let mut ctx = ServerCtx::new(Some(cred));
    match ctx.step(token, None) {
        Ok(_maybe_output_token) => {
            // Only a COMPLETE context authenticates. A multi-leg / SPNEGO
            // mechanism can return a source name mid-handshake while still
            // expecting further legs; treating that as authenticated would
            // accept a half-finished context. Gate on `is_complete()` and
            // only then read the established client principal.
            if !ctx.is_complete() {
                return GssResult::Continuation;
            }
            match ctx.source_name() {
                Ok(name) => GssResult::Authenticated(name.to_string()),
                Err(e) => GssResult::ServerError(format!(
                    "context complete but source name unavailable: {e}"
                )),
            }
        }
        Err(e) => GssResult::BadToken(format!("{e}")),
    }
}

/// Split `user@REALM` → (`user`, `Some(REALM)`); a name with no `@` → (name,
/// None).
pub fn split_principal(principal: &str) -> (String, Option<String>) {
    match principal.rsplit_once('@') {
        Some((user, realm)) if !realm.is_empty() => (user.to_owned(), Some(realm.to_owned())),
        _ => (principal.to_owned(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_principal() {
        assert_eq!(
            split_principal("alice@CORP.EXAMPLE.COM"),
            ("alice".into(), Some("CORP.EXAMPLE.COM".into()))
        );
        assert_eq!(split_principal("svc"), ("svc".into(), None));
    }

    #[test]
    fn register_bad_keytab_path_errors() {
        // A path with no NUL is fine to pass; a non-existent file makes MIT
        // krb5 register it lazily (error surfaces at acquire), so just exercise
        // the NUL guard here.
        assert!(register_keytab("/tmp/does-not-exist.keytab\0bad").is_err());
    }
}
