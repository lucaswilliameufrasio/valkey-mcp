use std::{collections::HashSet, net::SocketAddr};

use url::Url;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct Settings {
    pub bind_address: SocketAddr,
    pub control_database_url: Zeroizing<String>,
    pub oidc_issuer: Url,
    pub oidc_backchannel_url: Option<Url>,
    pub oidc_client_id: String,
    pub oidc_access_token_audience: String,
    pub mcp_public_url: Url,
    pub mcp_oauth_state_key: Zeroizing<String>,
    pub bootstrap_admin_subjects: HashSet<String>,
    pub vault_address: Url,
    pub vault_admin_token: Zeroizing<String>,
    pub vault_runtime_token: Zeroizing<String>,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("BIND_ADDRESS must be a valid socket address")]
    InvalidBindAddress,
    #[error("CONTROL_DATABASE_URL is required")]
    MissingControlDatabaseUrl,
    #[error("OIDC_ISSUER_URL must use HTTPS, except on loopback for local development")]
    InvalidOidcIssuer,
    #[error("OIDC_CLIENT_ID is required")]
    MissingOidcClientId,
    #[error("OIDC_ACCESS_TOKEN_AUDIENCE is required")]
    MissingOidcAccessTokenAudience,
    #[error("MCP_PUBLIC_URL must be an HTTPS origin, except on loopback for local development")]
    InvalidMcpPublicUrl,
    #[error("MCP_OAUTH_STATE_KEY must contain at least 32 bytes")]
    InvalidMcpOauthStateKey,
    #[error("OIDC_BOOTSTRAP_ADMIN_SUBJECTS must contain at least one subject")]
    MissingBootstrapAdministrators,
    #[error("VAULT_ADDRESS must use HTTPS, except on loopback for local development")]
    InvalidVaultAddress,
    #[error("VAULT_ADMIN_TOKEN and VAULT_RUNTIME_TOKEN are required")]
    MissingVaultTokens,
    #[error("VAULT_ADMIN_TOKEN and VAULT_RUNTIME_TOKEN must be different")]
    VaultTokensMustDiffer,
}

impl Settings {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let bind_address = std::env::var("BIND_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
            .parse()
            .map_err(|_| ConfigError::InvalidBindAddress)?;
        let control_database_url = required_environment("CONTROL_DATABASE_URL")
            .ok_or(ConfigError::MissingControlDatabaseUrl)?;
        let oidc_issuer = parse_http_url("OIDC_ISSUER_URL", ConfigError::InvalidOidcIssuer)?;
        let oidc_backchannel_url = optional_oidc_backchannel_url()?;
        let oidc_client_id =
            required_environment("OIDC_CLIENT_ID").ok_or(ConfigError::MissingOidcClientId)?;
        let oidc_access_token_audience = required_environment("OIDC_ACCESS_TOKEN_AUDIENCE")
            .ok_or(ConfigError::MissingOidcAccessTokenAudience)?;
        let mcp_public_url = parse_mcp_public_url(
            &required_environment("MCP_PUBLIC_URL").ok_or(ConfigError::InvalidMcpPublicUrl)?,
        )?;
        let mcp_oauth_state_key = required_environment("MCP_OAUTH_STATE_KEY")
            .filter(|key| key.len() >= 32)
            .ok_or(ConfigError::InvalidMcpOauthStateKey)?;
        let bootstrap_admin_subjects = std::env::var("OIDC_BOOTSTRAP_ADMIN_SUBJECTS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .map(str::to_owned)
            .collect::<HashSet<_>>();

        if bootstrap_admin_subjects.is_empty() {
            return Err(ConfigError::MissingBootstrapAdministrators);
        }

        let vault_address = parse_http_url("VAULT_ADDRESS", ConfigError::InvalidVaultAddress)?;
        let vault_admin_token =
            required_environment("VAULT_ADMIN_TOKEN").ok_or(ConfigError::MissingVaultTokens)?;
        let vault_runtime_token =
            required_environment("VAULT_RUNTIME_TOKEN").ok_or(ConfigError::MissingVaultTokens)?;
        if !vault_tokens_are_distinct(&vault_admin_token, &vault_runtime_token) {
            return Err(ConfigError::VaultTokensMustDiffer);
        }
        Ok(Self {
            bind_address,
            control_database_url: Zeroizing::new(control_database_url),
            oidc_issuer,
            oidc_backchannel_url,
            oidc_client_id,
            oidc_access_token_audience,
            mcp_public_url,
            mcp_oauth_state_key: Zeroizing::new(mcp_oauth_state_key),
            bootstrap_admin_subjects,
            vault_address,
            vault_admin_token: Zeroizing::new(vault_admin_token),
            vault_runtime_token: Zeroizing::new(vault_runtime_token),
        })
    }
}

fn parse_mcp_public_url(value: &str) -> Result<Url, ConfigError> {
    let mut url = Url::parse(value).map_err(|_| ConfigError::InvalidMcpPublicUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !has_secure_transport(&url)
    {
        return Err(ConfigError::InvalidMcpPublicUrl);
    }
    if url.path() != "/" {
        return Err(ConfigError::InvalidMcpPublicUrl);
    }
    url.set_path("");
    Ok(url)
}

fn required_environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn parse_http_url(name: &str, error: ConfigError) -> Result<Url, ConfigError> {
    let value = required_environment(name).ok_or_else(|| error.clone())?;
    let url = Url::parse(&value).map_err(|_| error.clone())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !has_secure_transport(&url)
    {
        return Err(error);
    }

    Ok(url)
}

fn optional_oidc_backchannel_url() -> Result<Option<Url>, ConfigError> {
    let Some(value) = required_environment("OIDC_BACKCHANNEL_URL") else {
        return Ok(None);
    };
    parse_oidc_backchannel_url(&value).map(Some)
}

fn parse_oidc_backchannel_url(value: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidOidcIssuer)?;
    let valid_origin = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    let valid_transport =
        url.scheme() == "https" || (url.scheme() == "http" && url.host_str() == Some("authentik"));
    if !valid_origin || !valid_transport {
        return Err(ConfigError::InvalidOidcIssuer);
    }
    Ok(url)
}

fn is_loopback_host(host: Option<&str>) -> bool {
    host.is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

fn has_secure_transport(url: &Url) -> bool {
    url.scheme() == "https" || (url.scheme() == "http" && is_loopback_host(url.host_str()))
}

fn vault_tokens_are_distinct(admin_token: &str, runtime_token: &str) -> bool {
    !admin_token.is_empty() && !runtime_token.is_empty() && admin_token != runtime_token
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::{
        has_secure_transport, is_loopback_host, parse_mcp_public_url, parse_oidc_backchannel_url,
        vault_tokens_are_distinct,
    };

    #[test]
    fn only_loopback_http_hosts_are_allowed_for_local_service_urls() {
        assert!(is_loopback_host(Some("localhost")));
        assert!(is_loopback_host(Some("127.0.0.1")));
        assert!(is_loopback_host(Some("::1")));
        let ipv6_loopback = Url::parse("http://[::1]").expect("valid loopback URL");
        assert!(is_loopback_host(ipv6_loopback.host_str()));
        assert!(!is_loopback_host(Some("localhost.attacker.example")));
        assert!(!is_loopback_host(Some("192.0.2.1")));

        let remote_http = Url::parse("http://oidc.example.test").expect("valid URL");
        let remote_https = Url::parse("https://oidc.example.test").expect("valid URL");
        assert!(!has_secure_transport(&remote_http));
        assert!(has_secure_transport(&remote_https));
        assert!(has_secure_transport(&ipv6_loopback));
    }

    #[test]
    fn vault_admin_and_runtime_credentials_must_be_distinct() {
        assert!(vault_tokens_are_distinct("admin-token", "runtime-token"));
        assert!(!vault_tokens_are_distinct("same-token", "same-token"));
        assert!(!vault_tokens_are_distinct("", "runtime-token"));
    }

    #[test]
    fn mcp_public_url_must_be_a_secure_origin_without_path() {
        let parsed =
            parse_mcp_public_url("https://mcp.example.test/").expect("secure origin is accepted");
        assert_eq!(parsed.as_str(), "https://mcp.example.test/");

        assert_eq!(
            parse_mcp_public_url("https://mcp.example.test/prefix"),
            Err(super::ConfigError::InvalidMcpPublicUrl)
        );
        assert_eq!(
            parse_mcp_public_url("http://mcp.example.test"),
            Err(super::ConfigError::InvalidMcpPublicUrl)
        );
    }

    #[test]
    fn oidc_backchannel_allows_only_authentik_http_or_secure_https_origins() {
        assert!(parse_oidc_backchannel_url("http://authentik:9000/").is_ok());
        assert!(parse_oidc_backchannel_url("https://identity.example.test/").is_ok());
        assert!(parse_oidc_backchannel_url("http://identity.example.test/").is_err());
        assert!(parse_oidc_backchannel_url("http://authentik:9000/provider").is_err());
    }
}
