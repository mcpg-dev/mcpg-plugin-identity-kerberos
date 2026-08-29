# `mcpg-plugin-identity-kerberos`

Kerberos / SPNEGO (HTTP **Negotiate**) identity plugin for mcpg
(`class: identity_provider`, `id: dev.mcpg.identity.kerberos`). Resolves the
caller's identity from an `Authorization: Negotiate <token>` header by
verifying the GSSAPI token against the gateway's service **keytab** (MIT
GSSAPI `accept_sec_context`) and reading the caller's Kerberos principal.

Part of the legacy → MCP bridge suite.

> **System dependency.** Builds against the system GSSAPI
> (`libkrb5-dev` / `libgssapi_krb5`). The crate is a workspace member but is
> kept **out of `default-members`**, so a plain `cargo build` does not require
> krb5-dev; build it explicitly with `-p mcpg-plugin-identity-kerberos`.


## Platforms

Published for **linux-gnu (amd64, arm64)** and **darwin-arm64** only.

`krb5` (MIT Kerberos) is a native C library, and no musl or Windows build of
this plugin exists because of it.

This matters at boot rather than at install. A gateway resolves a
platform-agnostic `oci:` reference to `protocol-<major>-<os>-<arch>` for the
host it is running on, and its only fallback is `wasi-wasm` — which this plugin
does not publish either. So on Alpine, on a musl-based image, or on Windows the
pull does not degrade: it fails, and the gateway does not start. Use a
glibc-based image, or an Apple-silicon host, when this plugin is in the config.

## How it works

Per resolve, given `Authorization: Negotiate <b64 SPNEGO/Kerberos token>`
(RFC 4559):

1. The scheme + base64 are parsed; a non-Negotiate header falls through
   (`None`).
2. The token is fed to `accept_sec_context` against the registered service
   keytab. This is a **local cryptographic check** — the keytab decrypts the
   service ticket the caller obtained from the KDC; the plugin makes **no
   outbound network call** (the KDC was contacted by the *client*).
3. On success the caller's Kerberos principal (`alice@CORP.EXAMPLE.COM`) is
   read via `gss_inquire_context` and mapped to the identity. A rejected /
   expired ticket → `Invalid`; an acceptor-side (keytab) error → `Invalid`
   (fail closed).

GSSAPI accept is synchronous and local, so — unlike the `oidc`/`ldap`
identity plugins — this carries **no private tokio runtime**.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `keytab` | string (required) | — | Path to the service keytab. Registered as the GSSAPI acceptor identity. A `${env.X}` / `vault://…` / `file://…` reference resolves to a path upstream. The file must exist at load. |
| `service_name` | string | — | Optional hostbased service to accept for (`HTTP@gateway.corp.example.com`). Omit to accept any principal in the keytab (the usual case). |
| `strip_realm` | bool | `true` | `subject_id` = the principal's local part (`alice@REALM` → `alice`); the full principal is always kept in `attributes.principal`. |
| `resolution.trust_level` | `verified`\|`header_asserted` | `verified` | Trust bucket for an authenticated caller. |
| `resolution.auth_provider_label` | string | `kerberos` | `auth_provider` on the identity. |

```yaml
plugins:
  - id: dev.mcpg.identity.kerberos
    class: identity_provider
    source: { oci: "{{OCI_BASE}}/identity-kerberos:<ver>" }
    config:
      keytab: "${env.MCPG_KEYTAB}"        # e.g. /etc/mcpg/http.keytab
      # service_name: "HTTP@gateway.corp.example.com"   # optional
      strip_realm: true
```

The operator's web server / reverse proxy negotiates `WWW-Authenticate:
Negotiate` with the client; mcpg receives the resulting `Authorization:
Negotiate` header and resolves the principal. The resolved identity
(`subject_id`, `attributes.principal`, `attributes.realm`) flows into the
gateway identity context for downstream policy + audit.

## Resolved identity

| Field | From |
|---|---|
| `subject_id` | principal local part (`strip_realm`) or the full principal. |
| `trust_level` / `kind` | `resolution.trust_level` (`verified`). |
| `auth_provider` | `resolution.auth_provider_label` (`kerberos`). |
| `issuer` | `krb5:<REALM>`. |
| `attributes.principal` | the full `user@REALM`. |
| `attributes.realm` | `REALM`. |

> Roles/groups are not populated. Active Directory group membership rides in
> the ticket's PAC; decoding the PAC is a follow-on (pair with an LDAP
> identity lookup in the meantime).

## Security

- **Local verification.** The token is verified against the keytab — no
  trust-on-first-use, no outbound call.
- **Fail closed.** A bad/expired ticket, an unparseable token, or an
  acceptor-side keytab error all resolve to `Invalid` (never a pass-through).
  Bad-token reasons are generic (no enumeration); details stay in logs.
- **No plaintext secrets.** The keytab is a file reference resolved by the
  gateway secret-resolver; the plugin never holds a password.
- **No OpenSSL.** MIT GSSAPI / libkrb5 only.

## Build / test

```bash
cargo build -p mcpg-plugin-identity-kerberos          # needs libkrb5-dev
cargo test  -p mcpg-plugin-identity-kerberos          # unit tests
# Real-KDC end-to-end (needs krb5-kdc + root to bind the KDC port):
cargo test -p mcpg-plugin-identity-kerberos --features integration-tests
```

The integration test stands up a throwaway MIT realm + `krb5kdc` in a temp
dir and runs a genuine two-sided GSSAPI handshake (client AS-REQ + TGS-REQ →
the plugin's `accept_sec_context`), proving a real Negotiate token resolves.

## Scope / deferred

- **PAC / AD group extraction** — `roles`/`groups` from the ticket's PAC.
- **Multi-leg negotiation** — v1 handles the single-leg Kerberos case (the
  norm); a continuation token resolves to `Invalid`.
- **Channel bindings** — not enforced in v1.
