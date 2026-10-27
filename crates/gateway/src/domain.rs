use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Type;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Type, PartialEq, Eq)]
#[sqlx(type_name = "access_level", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    Read,
    Write,
}

impl AccessLevel {
    pub fn allows(self, requested: Self) -> bool {
        matches!(
            (self, requested),
            (Self::Write, _) | (Self::Read, Self::Read)
        )
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Type, PartialEq, Eq)]
#[sqlx(type_name = "platform_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PlatformRole {
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Principal {
    pub id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub platform_role: PlatformRole,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}
