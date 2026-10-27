use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, query_as};
use uuid::Uuid;

use crate::{
    api_error::ApiError,
    auth::{AuthenticatedPrincipal, ensure_admin},
    domain::{AccessLevel, PlatformRole, Principal},
    integrations::IntegrationEngine,
    state::AppState,
};

#[derive(Serialize)]
pub struct AuthConfigResponse {
    pub issuer: String,
    pub client_id: String,
    pub resource: String,
    pub scopes: [&'static str; 3],
    pub mcp_endpoint: String,
    pub oauth_authorization_metadata_url: String,
}

pub async fn auth_config(State(state): State<AppState>) -> Json<AuthConfigResponse> {
    Json(AuthConfigResponse {
        issuer: state.oidc.issuer().to_owned(),
        client_id: state.oidc_client_id.to_string(),
        resource: state.oidc_access_token_audience.to_string(),
        scopes: ["openid", "profile", "email"],
        mcp_endpoint: state
            .mcp_public_url
            .join(&format!("{}/mcp", crate::SERVICE_KIND))
            .expect("configured MCP URL is valid")
            .to_string(),
        oauth_authorization_metadata_url: state
            .mcp_public_url
            .join(".well-known/oauth-authorization-server")
            .expect("configured MCP URL is valid")
            .to_string(),
    })
}

#[derive(Serialize)]
pub struct MeResponse {
    pub principal: Principal,
}

pub async fn me(
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
) -> Json<MeResponse> {
    Json(MeResponse { principal: actor.0 })
}

#[derive(Serialize)]
pub struct PrincipalSummary {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub platform_role: PlatformRole,
    pub enabled: bool,
    pub last_seen_at: Option<DateTime<Utc>>,
}

pub async fn list_principals(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
) -> Result<Json<Vec<PrincipalSummary>>, ApiError> {
    ensure_admin(&actor.0)?;
    let principals = query_as::<_, Principal>(
        "SELECT id, issuer, subject, email, display_name, platform_role, enabled, created_at, last_seen_at \
         FROM principals ORDER BY last_seen_at DESC NULLS LAST, created_at DESC LIMIT 500",
    )
    .fetch_all(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?
    .into_iter()
    .map(|principal| PrincipalSummary {
        id: principal.id,
        issuer: principal.issuer,
        subject: principal.subject,
        email: principal.email,
        display_name: principal.display_name,
        platform_role: principal.platform_role,
        enabled: principal.enabled,
        last_seen_at: principal.last_seen_at,
    })
    .collect();

    Ok(Json(principals))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub limit: Option<i64>,
}

#[derive(Serialize, FromRow)]
pub struct AuditEventView {
    pub id: Uuid,
    pub principal_id: Option<Uuid>,
    pub issuer: String,
    pub subject: String,
    pub integration_id: Option<Uuid>,
    pub integration_name: Option<String>,
    pub integration_engine: Option<IntegrationEngine>,
    pub resource_name: Option<String>,
    pub operation: String,
    pub access_level: Option<AccessLevel>,
    pub outcome: String,
    pub error_code: Option<String>,
    pub query_fingerprint: Option<String>,
    pub database_principal: Option<String>,
    pub vault_lease_fingerprint: Option<String>,
    pub duration_ms: Option<i64>,
    pub created_at: DateTime<Utc>,
}

pub async fn list_audit_events(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<AuthenticatedPrincipal>,
    Query(input): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEventView>>, ApiError> {
    ensure_admin(&actor.0)?;
    let limit = input.limit.unwrap_or(100).clamp(1, 200);
    let events = query_as::<_, AuditEventView>(
        "SELECT a.id, a.principal_id, a.issuer, a.subject, a.integration_id, \
                t.name AS integration_name, t.engine AS integration_engine, \
                a.resource_name, a.operation, a.access_level, \
                a.outcome, a.error_code, a.query_fingerprint, a.database_principal, \
                a.vault_lease_fingerprint, a.duration_ms, a.created_at \
         FROM audit_events a JOIN integration_targets t ON t.id = a.integration_id \
         ORDER BY a.created_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(&state.control_pool)
    .await
    .map_err(|_| ApiError::DependencyUnavailable)?;

    Ok(Json(events))
}
