use std::{net::IpAddr, time::Duration};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, query, query_as};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    api_error::ApiError,
    auth::{AuthenticatedPrincipal, ensure_admin},
    domain::AccessLevel,
    state::AppState,
};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, sqlx::Type, PartialEq, Eq)]
#[sqlx(type_name = "integration_engine", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IntegrationEngine {
    Nats,
    Valkey,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct IntegrationTarget {
    pub id: Uuid,
    pub name: String,
    pub engine: IntegrationEngine,
    pub host: String,
    pub port: i32,
    pub tls_enabled: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(try_from = "String")]
struct SecretInput(Zeroizing<String>);

impl TryFrom<String> for SecretInput {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() || value.len() > 4096 {
            return Err("credential is outside the accepted size");
        }
        Ok(Self(Zeroizing::new(value)))
    }
}

#[derive(Deserialize)]
pub struct RegisterIntegrationRequest {
    name: String,
    engine: IntegrationEngine,
    host: String,
    port: u16,
    #[serde(default = "default_tls")]
    tls_enabled: bool,
    #[serde(default)]
    username: Option<String>,
    password: SecretInput,
}

#[derive(Serialize)]
pub struct IntegrationRegistrationResponse {
    target: IntegrationTarget,
    credential_stored_in_vault: bool,
}

fn default_tls() -> bool {
    true
}

pub async fn list_targets(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Query(filter): Query<TargetFilter>,
) -> Result<Json<Vec<IntegrationTarget>>, ApiError> {
    ensure_admin(&actor.0)?;
    let targets = query_as::<_, IntegrationTarget>(
        "SELECT id, name, engine, host, port, tls_enabled, enabled, created_at \
         FROM integration_targets WHERE engine = 'valkey' \
         AND ($1::integration_engine IS NULL OR engine = $1) \
         ORDER BY engine, name",
    )
    .bind(filter.engine)
    .fetch_all(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;

    Ok(Json(targets))
}

#[derive(Deserialize)]
pub struct TargetFilter {
    engine: Option<IntegrationEngine>,
}

pub async fn register_target(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Json(input): Json<RegisterIntegrationRequest>,
) -> Result<(StatusCode, Json<IntegrationRegistrationResponse>), ApiError> {
    ensure_admin(&actor.0)?;
    validate_input(&input)?;
    if input.engine != IntegrationEngine::Valkey {
        return Err(ApiError::InvalidRequest);
    }

    let duplicate: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM integration_targets WHERE name = $1)")
            .bind(input.name.trim())
            .fetch_one(&state.control_pool)
            .await
            .map_err(|_| ApiError::DependencyUnavailable)?;
    if duplicate {
        return Err(ApiError::Conflict);
    }

    let target_id = Uuid::now_v7();
    let secret_path = format!("{}/{target_id}", engine_name(input.engine));
    let host = input.host.trim();
    test_connection(&input, host).await?;

    state
        .vault_admin
        .write_integration_secret(
            &secret_path,
            input.username.as_deref().unwrap_or_default(),
            input.password.0.as_str(),
        )
        .await
        .map_err(|_| ApiError::DependencyUnavailable)?;

    let inserted = query_as::<_, IntegrationTarget>(
        "INSERT INTO integration_targets \
         (id, name, engine, host, port, tls_enabled, vault_secret_path, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         RETURNING id, name, engine, host, port, tls_enabled, enabled, created_at",
    )
    .bind(target_id)
    .bind(input.name.trim())
    .bind(input.engine)
    .bind(host)
    .bind(i32::from(input.port))
    .bind(input.tls_enabled)
    .bind(&secret_path)
    .bind(actor.0.id)
    .fetch_one(&state.control_pool)
    .await;

    let target = match inserted {
        Ok(target) => target,
        Err(error) => {
            let _ = state
                .vault_admin
                .delete_integration_secret(&secret_path)
                .await;
            if matches!(&error, sqlx::Error::Database(database_error) if database_error.code().as_deref() == Some("23505"))
            {
                return Err(ApiError::Conflict);
            }
            return Err(ApiError::DependencyUnavailable);
        }
    };

    Ok((
        StatusCode::CREATED,
        Json(IntegrationRegistrationResponse {
            target,
            credential_stored_in_vault: true,
        }),
    ))
}

pub async fn set_target_enabled(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Path(target_id): Path<Uuid>,
    Json(input): Json<SetEnabledRequest>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&actor.0)?;
    let result =
        query("UPDATE integration_targets SET enabled = $1, updated_at = NOW() WHERE id = $2 AND engine = 'valkey'")
            .bind(input.enabled)
            .bind(target_id)
            .execute(&state.control_pool)
            .await
            .map_err(|_| ApiError::DependencyUnavailable)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    record_admin_audit(
        &state,
        &actor,
        target_id,
        if input.enabled {
            "integration_enabled"
        } else {
            "integration_paused"
        },
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ReplaceCredentialRequest {
    #[serde(default)]
    username: Option<String>,
    password: SecretInput,
}

#[derive(FromRow)]
struct CredentialTarget {
    id: Uuid,
    name: String,
    engine: IntegrationEngine,
    host: String,
    port: i32,
    tls_enabled: bool,
    vault_secret_path: String,
}

pub async fn replace_credential(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Path(target_id): Path<Uuid>,
    Json(input): Json<ReplaceCredentialRequest>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&actor.0)?;
    if input
        .username
        .as_ref()
        .is_some_and(|username| username.len() > 256)
    {
        return Err(ApiError::InvalidRequest);
    }

    let target = query_as::<_, CredentialTarget>(
        "SELECT id, name, engine, host, port, tls_enabled, vault_secret_path \
         FROM integration_targets WHERE id = $1 AND engine = 'valkey'",
    )
    .bind(target_id)
    .fetch_optional(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?
    .ok_or(ApiError::NotFound)?;
    if target.engine != IntegrationEngine::Valkey {
        return Err(ApiError::NotFound);
    }

    let test_input = RegisterIntegrationRequest {
        name: target.name,
        engine: target.engine,
        host: target.host.clone(),
        port: u16::try_from(target.port).map_err(|_| ApiError::InvalidRequest)?,
        tls_enabled: target.tls_enabled,
        username: input.username,
        password: input.password,
    };
    test_connection(&test_input, &target.host).await?;
    state
        .vault_admin
        .write_integration_secret(
            &target.vault_secret_path,
            test_input.username.as_deref().unwrap_or_default(),
            test_input.password.0.as_str(),
        )
        .await
        .map_err(|_| ApiError::DependencyUnavailable)?;
    record_admin_audit(&state, &actor, target.id, "integration_credential_replaced").await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SetEnabledRequest {
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct IntegrationGrant {
    pub integration_id: Uuid,
    pub integration_name: String,
    pub access_level: AccessLevel,
    pub resource_scope: String,
    pub granted_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct SetGrantRequest {
    access_level: AccessLevel,
    resource_scope: String,
}

pub async fn list_principal_grants(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Path(principal_id): Path<Uuid>,
) -> Result<Json<Vec<IntegrationGrant>>, ApiError> {
    ensure_admin(&actor.0)?;
    let grants = query_as::<_, IntegrationGrant>(
        "SELECT g.integration_id, t.name AS integration_name, g.access_level, \
                g.resource_scope, g.granted_at \
         FROM principal_integration_grants g \
         JOIN integration_targets t ON t.id = g.integration_id \
          WHERE g.principal_id = $1 AND t.engine = 'valkey' ORDER BY t.name",
    )
    .bind(principal_id)
    .fetch_all(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;
    Ok(Json(grants))
}

pub async fn set_grant(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Path((principal_id, target_id)): Path<(Uuid, Uuid)>,
    Json(input): Json<SetGrantRequest>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&actor.0)?;
    let resource_scope = input.resource_scope.trim();
    if !valid_resource_scope(&state, target_id, resource_scope).await? {
        return Err(ApiError::InvalidRequest);
    }

    let result = query(
        "INSERT INTO principal_integration_grants \
         (principal_id, integration_id, access_level, resource_scope, granted_by) \
         SELECT $1, t.id, $3, $4, $5 FROM integration_targets t \
         JOIN principals p ON p.id = $1 AND p.enabled = TRUE \
          WHERE t.id = $2 AND t.enabled = TRUE AND t.engine = 'valkey' \
         ON CONFLICT (principal_id, integration_id) DO UPDATE SET \
             access_level = EXCLUDED.access_level, \
             resource_scope = EXCLUDED.resource_scope, \
             granted_by = EXCLUDED.granted_by, granted_at = NOW()",
    )
    .bind(principal_id)
    .bind(target_id)
    .bind(input.access_level)
    .bind(resource_scope)
    .bind(actor.0.id)
    .execute(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    record_admin_audit(&state, &actor, target_id, "integration_grant_updated").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn valid_resource_scope(
    state: &AppState,
    target_id: Uuid,
    scope: &str,
) -> Result<bool, ApiError> {
    if scope.is_empty() || scope.len() > 256 {
        return Ok(false);
    }
    let engine: Option<IntegrationEngine> = sqlx::query_scalar(
        "SELECT engine FROM integration_targets WHERE id = $1 AND enabled = TRUE AND engine = 'valkey'",
    )
    .bind(target_id)
    .fetch_optional(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;
    let Some(engine) = engine else {
        return Err(ApiError::NotFound);
    };

    Ok(resource_scope_is_valid(engine, scope))
}

fn resource_scope_is_valid(engine: IntegrationEngine, scope: &str) -> bool {
    if scope.is_empty() || scope.len() > 256 {
        return false;
    }
    match engine {
        IntegrationEngine::Nats => {
            scope.strip_suffix('.').is_some_and(|prefix| {
                !prefix.is_empty()
                    && prefix.split('.').all(|part| {
                        !part.is_empty()
                            && part.chars().all(|character| {
                                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                            })
                    })
            }) && !scope.contains('*')
                && !scope.contains('>')
        }
        IntegrationEngine::Valkey => scope.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '_' | '-' | '.')
        }),
    }
}

pub async fn delete_grant(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Path((principal_id, target_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    ensure_admin(&actor.0)?;
    let result = query(
        "DELETE FROM principal_integration_grants \
         WHERE principal_id = $1 AND integration_id = $2 \
         AND integration_id IN (SELECT id FROM integration_targets WHERE engine = 'valkey')",
    )
    .bind(principal_id)
    .bind(target_id)
    .execute(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    record_admin_audit(&state, &actor, target_id, "integration_grant_revoked").await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn record_admin_audit(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    target_id: Uuid,
    operation: &str,
) -> Result<(), ApiError> {
    query(
        "INSERT INTO audit_events \
         (id, principal_id, issuer, subject, integration_id, operation, outcome) \
         VALUES ($1, $2, $3, $4, $5, $6, 'success')",
    )
    .bind(Uuid::now_v7())
    .bind(actor.0.id)
    .bind(&actor.0.issuer)
    .bind(&actor.0.subject)
    .bind(target_id)
    .bind(operation)
    .execute(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;
    Ok(())
}

fn validate_input(input: &RegisterIntegrationRequest) -> Result<(), ApiError> {
    let name = input.name.trim();
    let host = input.host.trim();
    if name.is_empty()
        || name.len() > 80
        || host.is_empty()
        || host.len() > 253
        || !valid_host(host)
        || input.port == 0
        || input.password.0.is_empty()
        || input
            .username
            .as_ref()
            .is_some_and(|username| username.len() > 256)
        || (!input.tls_enabled && !is_local_insecure_host(host))
    {
        return Err(ApiError::InvalidRequest);
    }

    Ok(())
}

async fn test_connection(input: &RegisterIntegrationRequest, host: &str) -> Result<(), ApiError> {
    let host = endpoint_host(host);
    let address = format!(
        "{}://{}:{}",
        if input.tls_enabled {
            match input.engine {
                IntegrationEngine::Nats => "tls",
                IntegrationEngine::Valkey => "rediss",
            }
        } else {
            match input.engine {
                IntegrationEngine::Nats => "nats",
                IntegrationEngine::Valkey => "redis",
            }
        },
        host,
        input.port
    );

    match input.engine {
        IntegrationEngine::Nats => {
            let options = match input.username.as_deref() {
                Some(username) if !username.is_empty() => {
                    async_nats::ConnectOptions::with_user_and_password(
                        username.to_owned(),
                        input.password.0.to_string(),
                    )
                }
                _ => async_nats::ConnectOptions::with_token(input.password.0.to_string()),
            }
            .require_tls(input.tls_enabled);
            let nats_address = address.replace("tls://", "nats://");
            let client =
                tokio::time::timeout(Duration::from_secs(5), options.connect(nats_address))
                    .await
                    .map_err(|_| ApiError::DependencyUnavailable)?
                    .map_err(|_| ApiError::DependencyUnavailable)?;
            tokio::time::timeout(Duration::from_secs(5), client.flush())
                .await
                .map_err(|_| ApiError::DependencyUnavailable)?
                .map_err(|_| ApiError::DependencyUnavailable)?;
            Ok(())
        }
        IntegrationEngine::Valkey => {
            let mut url = Url::parse(&address).map_err(|_| ApiError::InvalidRequest)?;
            if let Some(username) = input
                .username
                .as_deref()
                .filter(|username| !username.is_empty())
            {
                url.set_username(username)
                    .map_err(|_| ApiError::InvalidRequest)?;
            }
            url.set_password(Some(input.password.0.as_str()))
                .map_err(|_| ApiError::InvalidRequest)?;
            let client = redis::Client::open(url.as_str()).map_err(|_| ApiError::InvalidRequest)?;
            let mut connection = tokio::time::timeout(
                Duration::from_secs(5),
                client.get_multiplexed_async_connection(),
            )
            .await
            .map_err(|_| ApiError::DependencyUnavailable)?
            .map_err(|_| ApiError::DependencyUnavailable)?;
            let _: String = tokio::time::timeout(
                Duration::from_secs(5),
                redis::cmd("PING").query_async(&mut connection),
            )
            .await
            .map_err(|_| ApiError::DependencyUnavailable)?
            .map_err(|_| ApiError::DependencyUnavailable)?;
            Ok(())
        }
    }
}

fn engine_name(engine: IntegrationEngine) -> &'static str {
    match engine {
        IntegrationEngine::Nats => "nats",
        IntegrationEngine::Valkey => "valkey",
    }
}

fn is_local_insecure_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("target-nats")
        || host.eq_ignore_ascii_case("target-valkey")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn endpoint_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IntegrationEngine, RegisterIntegrationRequest, SecretInput, endpoint_host,
        is_local_insecure_host, resource_scope_is_valid, test_connection, valid_host,
    };
    use zeroize::Zeroizing;

    #[test]
    fn scopes_reject_wildcards_and_require_domain_specific_prefixes() {
        assert!(resource_scope_is_valid(
            IntegrationEngine::Nats,
            "orders.events."
        ));
        assert!(!resource_scope_is_valid(
            IntegrationEngine::Nats,
            "orders.>"
        ));
        assert!(!resource_scope_is_valid(IntegrationEngine::Nats, "*"));
        assert!(!resource_scope_is_valid(
            IntegrationEngine::Nats,
            "orders..events."
        ));
        assert!(resource_scope_is_valid(
            IntegrationEngine::Valkey,
            "orders:customer:"
        ));
        assert!(!resource_scope_is_valid(
            IntegrationEngine::Valkey,
            "orders:*"
        ));
        assert!(!resource_scope_is_valid(IntegrationEngine::Valkey, ""));
    }

    #[test]
    fn connection_hosts_reject_url_injection_and_malformed_labels() {
        assert!(valid_host("nats.internal.example"));
        assert!(valid_host("127.0.0.1"));
        assert!(is_local_insecure_host("target-nats"));
        assert!(is_local_insecure_host("target-valkey"));
        assert!(!is_local_insecure_host("valkey.internal"));
        assert!(!valid_host("nats.internal:4222"));
        assert!(!valid_host("nats.internal/path"));
        assert!(!valid_host("-invalid.example"));
        assert_eq!(endpoint_host("::1"), "[::1]");
    }

    #[tokio::test]
    #[ignore = "requires an isolated authenticated Valkey test service"]
    async fn live_valkey_connection_accepts_credentials() {
        let valkey_port = std::env::var("VALKEY_MCP_TEST_PORT")
            .expect("set VALKEY_MCP_TEST_PORT to the isolated Valkey service port")
            .parse::<u16>()
            .expect("Valkey port should be valid");
        let valkey_password = std::env::var("VALKEY_MCP_TEST_PASSWORD")
            .expect("set VALKEY_MCP_TEST_PASSWORD for the isolated Valkey service");
        let valkey = RegisterIntegrationRequest {
            name: "synthetic-valkey".to_owned(),
            engine: IntegrationEngine::Valkey,
            host: "127.0.0.1".to_owned(),
            port: valkey_port,
            tls_enabled: false,
            username: None,
            password: SecretInput(Zeroizing::new(valkey_password)),
        };
        test_connection(&valkey, &valkey.host)
            .await
            .expect("the isolated authenticated Valkey service should accept the password");
    }
}
