//! Per-provider `base_url` validation (SSRF + API-key-exfiltration defense — C5-SEC-1).
//!
//! `ubi_setOracleConfig` lets a (loopback) caller repoint which endpoint the node's LLM backend dials.
//! Without validation that is a server-side request forgery primitive (point the node at
//! `http://169.254.169.254/` / `http://127.0.0.1:<port>/` / an internal k8s service) **and** an
//! API-key-exfiltration primitive (the operator's real provider key rides the `Authorization: Bearer`
//! header to whatever host the attacker named). This module is the single chokepoint that decides whether
//! a configured `base_url` is allowed to be dialed, **per provider**:
//!
//!   * **Anthropic** — the endpoint is pinned in [`crate::client`]; a configured `base_url`, if present,
//!     MUST be `https` to host `api.anthropic.com`. Anything else is refused (we never silently ignore a
//!     misleading config).
//!   * **OpenAI-compatible** — MUST be `https`; we RESOLVE the host and refuse if **any** resolved IP is
//!     loopback / link-local / RFC1918-private / unique-local / the `169.254.169.254` metadata address.
//!     A *public* https host (OpenAI / OpenRouter / Groq / …) is allowed — that is the feature; only
//!     internal/metadata targets are blocked. The API key is attached **only** to a host that passes this
//!     check, so a repointed `base_url` can never ride the operator's key to an internal target.
//!   * **Ollama** — the one place loopback is *allowed*: `http`/`https` to `localhost` / `127.0.0.1` /
//!     `::1` only. No key is ever attached to Ollama.
//!
//! The check resolves DNS (via [`std::net::ToSocketAddrs`]) and inspects **every** returned address, so a
//! hostname that resolves to an internal IP (DNS-rebinding-style) is refused too. Resolution failure on a
//! provider that requires it is a hard refusal (fail-closed). Transports additionally disable HTTP
//! redirects so a `3xx` cannot bounce the key to a different host.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use crate::backend::Provider;

/// The Anthropic API host (the only host the Anthropic provider may be pointed at).
pub const ANTHROPIC_HOST: &str = "api.anthropic.com";

/// A `base_url` was refused by the per-provider policy. The message is operator-facing and secret-free
/// (it only ever names the offending URL/host/scheme — never a key value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPolicyError(pub String);

impl std::fmt::Display for UrlPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected base_url: {}", self.0)
    }
}

impl std::error::Error for UrlPolicyError {}

/// A minimally-parsed URL: just the pieces the policy needs. We avoid pulling a URL crate; the shape we
/// accept is `scheme://host[:port][/path]` which is all a provider base ever is.
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
}

/// Parse `scheme://host[:port][/...]`. Rejects anything without an explicit `http`/`https` scheme and a
/// non-empty host. IPv6 literal hosts are accepted in bracket form (`[::1]`).
fn parse_url(raw: &str) -> Result<ParsedUrl, UrlPolicyError> {
    let raw = raw.trim();
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| UrlPolicyError(format!("{raw} (missing scheme://)")))?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(UrlPolicyError(format!("{raw} (scheme must be http/https)")));
    }
    // Strip path / query / fragment — we only authorize the authority (host:port).
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    if authority.is_empty() {
        return Err(UrlPolicyError(format!("{raw} (missing host)")));
    }
    // Strip userinfo if present (`user:pass@host`) — never an allowed shape for a provider base.
    if authority.contains('@') {
        return Err(UrlPolicyError(format!("{raw} (userinfo not allowed)")));
    }
    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:port`.
        let (h, p) = after_bracket
            .split_once(']')
            .ok_or_else(|| UrlPolicyError(format!("{raw} (malformed IPv6 host)")))?;
        let port = p
            .strip_prefix(':')
            .map(|s| s.parse::<u16>())
            .transpose()
            .map_err(|_| UrlPolicyError(format!("{raw} (bad port)")))?;
        (h.to_string(), port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        // Could be host:port, but only treat the suffix as a port if it parses as one (a bare IPv6
        // without brackets won't, and we reject those below as a malformed host anyway).
        match p.parse::<u16>() {
            Ok(port) => (h.to_string(), Some(port)),
            Err(_) => (authority.to_string(), None),
        }
    } else {
        (authority.to_string(), None)
    };
    if host.is_empty() {
        return Err(UrlPolicyError(format!("{raw} (empty host)")));
    }
    Ok(ParsedUrl {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// Is `ip` an address we must never let the node dial for a cloud provider? Covers loopback,
/// link-local (incl. the `169.254.169.254` cloud-metadata address), RFC1918 private v4, unique-local v6
/// (`fc00::/7`), unspecified, and IPv4-mapped/compat v6 wrappers of the above.
pub fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_internal_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_internal_v4(&mapped);
            }
            // `to_ipv4()` also catches IPv4-compatible (deprecated) addresses.
            if let Some(compat) = v6.to_ipv4() {
                if is_internal_v4(&compat) {
                    return true;
                }
            }
            is_internal_v6(v6)
        }
    }
}

fn is_internal_v4(v4: &Ipv4Addr) -> bool {
    v4.is_loopback()            // 127.0.0.0/8
        || v4.is_private()      // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()   // 169.254.0.0/16 (incl. 169.254.169.254 metadata)
        || v4.is_unspecified()  // 0.0.0.0
        || v4.is_broadcast()
        || v4.octets()[0] == 0 // 0.0.0.0/8
}

fn is_internal_v6(v6: &Ipv6Addr) -> bool {
    v6.is_loopback()            // ::1
        || v6.is_unspecified()  // ::
        || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local (ULA)
        || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
}

/// Is `host` a literal loopback host (the only authority Ollama is allowed to use)? Accepts the literal
/// IPs `127.0.0.1` / `::1`, any `127.0.0.0/8` v4 literal, and the name `localhost`.
fn is_loopback_host(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => false,
    }
}

/// Validate a configured `base_url` for `provider`, deciding whether the node may dial it.
///
/// * `None`/empty `base_url` is always OK (the provider falls back to its pinned/default endpoint).
/// * Anthropic: if present, must be `https://api.anthropic.com` (host pinned, scheme https).
/// * OpenAI-compatible: must be `https`; the host is resolved and refused if any resolved IP is internal
///   (loopback/link-local/RFC1918/ULA/metadata). Public hosts pass.
/// * Ollama: `http`/`https` to a loopback host only (`localhost`/`127.0.0.1`/`::1`).
///
/// Returns `Ok(())` if the node may dial it, or [`UrlPolicyError`] (secret-free) if it must be refused.
pub fn validate_base_url(provider: Provider, base_url: Option<&str>) -> Result<(), UrlPolicyError> {
    let raw = match base_url.map(str::trim).filter(|s| !s.is_empty()) {
        None => return Ok(()), // no override ⇒ provider default endpoint (already trusted)
        Some(s) => s,
    };
    let url = parse_url(raw)?;
    match provider {
        Provider::Anthropic => {
            if url.scheme != "https" {
                return Err(UrlPolicyError(format!("{raw} (anthropic requires https)")));
            }
            if url.host != ANTHROPIC_HOST {
                return Err(UrlPolicyError(format!(
                    "{raw} (anthropic host must be {ANTHROPIC_HOST})"
                )));
            }
            Ok(())
        }
        Provider::Ollama => {
            if !is_loopback_host(&url.host) {
                return Err(UrlPolicyError(format!(
                    "{raw} (ollama base_url must be loopback: localhost/127.0.0.1/::1)"
                )));
            }
            Ok(())
        }
        Provider::Openai => {
            if url.scheme != "https" {
                return Err(UrlPolicyError(format!(
                    "{raw} (openai-compatible base_url requires https)"
                )));
            }
            // Resolve the host and refuse if ANY resolved address is internal. A bare IP literal resolves
            // to itself; a hostname is resolved via the system resolver and every returned IP is checked.
            let addrs = resolve_host(&url.host, url.port.unwrap_or(443))?;
            for ip in &addrs {
                if is_internal_ip(ip) {
                    return Err(UrlPolicyError(format!(
                        "{raw} (host resolves to an internal/metadata address {ip}; SSRF blocked)"
                    )));
                }
            }
            Ok(())
        }
    }
}

/// Resolve `host:port` to its IP addresses. A literal IP resolves to itself without touching DNS. A
/// resolution failure is a hard refusal (fail-closed) for the provider that requires resolution.
fn resolve_host(host: &str, port: u16) -> Result<Vec<IpAddr>, UrlPolicyError> {
    // Literal IP: no DNS, resolve to itself (covers `https://10.0.0.5`, `https://[::1]`, etc.).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let iter = (host, port)
        .to_socket_addrs()
        .map_err(|e| UrlPolicyError(format!("{host} (DNS resolution failed: {e})")))?;
    let ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
    if ips.is_empty() {
        return Err(UrlPolicyError(format!("{host} (host did not resolve)")));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_requires_pinned_https_host() {
        assert!(validate_base_url(Provider::Anthropic, None).is_ok());
        assert!(validate_base_url(Provider::Anthropic, Some("")).is_ok());
        assert!(validate_base_url(Provider::Anthropic, Some("https://api.anthropic.com")).is_ok());
        assert!(validate_base_url(
            Provider::Anthropic,
            Some("https://api.anthropic.com/v1/messages")
        )
        .is_ok());
        // Wrong host / scheme / an attacker URL are all refused.
        assert!(validate_base_url(Provider::Anthropic, Some("http://api.anthropic.com")).is_err());
        assert!(validate_base_url(Provider::Anthropic, Some("https://evil.example.com")).is_err());
        assert!(validate_base_url(
            Provider::Anthropic,
            Some("https://api.anthropic.com.evil.com")
        )
        .is_err());
    }

    #[test]
    fn ollama_allows_only_loopback() {
        for ok in [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://[::1]:11434",
            "https://localhost",
            "http://127.0.0.5:11434",
        ] {
            assert!(
                validate_base_url(Provider::Ollama, Some(ok)).is_ok(),
                "{ok} should pass for ollama"
            );
        }
        for bad in [
            "http://attacker.evil:1234",
            "http://10.0.0.5:11434",
            "http://169.254.169.254",
            "http://192.168.1.2:11434",
        ] {
            assert!(
                validate_base_url(Provider::Ollama, Some(bad)).is_err(),
                "{bad} must be refused for ollama"
            );
        }
    }

    #[test]
    fn openai_rejects_internal_targets_and_non_https() {
        // Internal/metadata literal targets are refused.
        for bad in [
            "http://169.254.169.254/",      // not https
            "https://169.254.169.254/",     // metadata
            "https://127.0.0.1:9000/admin", // loopback
            "https://10.0.0.5/v1",          // RFC1918
            "https://192.168.1.10/v1",      // RFC1918
            "https://172.16.0.1/v1",        // RFC1918
            "https://[::1]:6379/",          // loopback v6
            "https://[fd00::1]/",           // ULA
            "https://[fe80::1]/",           // link-local v6
            "https://0.0.0.0/",             // unspecified
        ] {
            assert!(
                validate_base_url(Provider::Openai, Some(bad)).is_err(),
                "{bad} must be refused for openai"
            );
        }
    }

    #[test]
    fn openai_allows_public_https_literal() {
        // A public IP literal passes (resolves to itself, not internal). 1.1.1.1 is a public address.
        assert!(validate_base_url(Provider::Openai, Some("https://1.1.1.1/v1")).is_ok());
    }

    #[test]
    fn ipv4_mapped_v6_loopback_is_internal() {
        // `::ffff:127.0.0.1` must be treated as loopback (mapped form).
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_internal_ip(&ip));
        let meta: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_internal_ip(&meta));
    }

    #[test]
    fn malformed_urls_are_refused() {
        for bad in [
            "not-a-url",
            "ftp://example.com",
            "https://",
            "file:///etc/passwd",
            "https://user:pass@evil.com",
        ] {
            assert!(
                validate_base_url(Provider::Openai, Some(bad)).is_err(),
                "{bad} must be refused"
            );
        }
    }
}
