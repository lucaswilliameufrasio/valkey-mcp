use std::time::Duration;

use reqwest::{Client, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::VaultError;

const SECRET_MOUNT: &str = "integration-secrets";

pub struct VaultClient {
    address: Url,
    token: Zeroizing<String>,
    http: Client,
}

impl VaultClient {
    pub fn new(address: Url, token: Zeroizing<String>) -> Result<Self, VaultError> {
        if token.is_empty() {
            return Err(VaultError::EmptyToken);
        }
        if !matches!(address.scheme(), "http" | "https")
            || address.host_str().is_none()
            || !address.username().is_empty()
            || address.password().is_some()
            || address.query().is_some()
            || address.fragment().is_some()
            || (address.scheme() != "https" && !is_loopback_host(address.host_str()))
        {
            return Err(VaultError::InvalidAddress);
        }

        let http = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| VaultError::RequestFailed)?;
        Ok(Self {
            address,
            token,
            http,
        })
    }

    pub async fn write_integration_secret(
        &self,
        path: &str,
        username: &str,
        password: &str,
    ) -> Result<(), VaultError> {
        validate_secret_path(path)?;
        if username.len() > 256 || password.is_empty() || password.len() > 4096 {
            return Err(VaultError::InvalidSecret);
        }
        let endpoint = self.endpoint(&[SECRET_MOUNT, "data", path])?;
        let response = self
            .http
            .post(endpoint)
            .header("X-Vault-Token", self.token.as_str())
            .json(&KvWriteRequest {
                data: KvCredentialData { username, password },
            })
            .send()
            .await
            .map_err(|_| VaultError::RequestFailed)?;
        ensure_success(response.status())
    }

    pub async fn read_integration_secret(
        &self,
        path: &str,
    ) -> Result<IntegrationSecret, VaultError> {
        validate_secret_path(path)?;
        let endpoint = self.endpoint(&[SECRET_MOUNT, "data", path])?;
        let response = self
            .http
            .get(endpoint)
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .await
            .map_err(|_| VaultError::RequestFailed)?;
        ensure_success(response.status())?;
        let response = response
            .json::<KvReadResponse>()
            .await
            .map_err(|_| VaultError::InvalidSecret)?;
        if response.data.data.password.as_str().is_empty() {
            return Err(VaultError::InvalidSecret);
        }
        Ok(IntegrationSecret {
            username: response.data.data.username.into_inner(),
            password: response.data.data.password.into_inner(),
        })
    }

    pub async fn delete_integration_secret(&self, path: &str) -> Result<(), VaultError> {
        validate_secret_path(path)?;
        let endpoint = self.endpoint(&[SECRET_MOUNT, "metadata", path])?;
        let response = self
            .http
            .delete(endpoint)
            .header("X-Vault-Token", self.token.as_str())
            .send()
            .await
            .map_err(|_| VaultError::RequestFailed)?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        ensure_success(status)
    }

    fn endpoint(&self, path: &[&str]) -> Result<Url, VaultError> {
        let mut endpoint = self.address.clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|_| VaultError::InvalidAddress)?;
        segments.pop_if_empty();
        segments.push("v1");
        for segment in path {
            for path_segment in segment.split('/') {
                segments.push(path_segment);
            }
        }
        drop(segments);
        Ok(endpoint)
    }
}

pub struct IntegrationSecret {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

fn validate_secret_path(path: &str) -> Result<(), VaultError> {
    if path.is_empty()
        || path.len() > 256
        || path.split('/').any(|segment| {
            segment.is_empty()
                || matches!(segment, "." | "..")
                || !segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
        })
    {
        return Err(VaultError::InvalidSecret);
    }
    Ok(())
}

fn ensure_success(status: StatusCode) -> Result<(), VaultError> {
    if status.is_success() {
        Ok(())
    } else {
        Err(VaultError::Rejected(status.as_u16()))
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "[::1]"))
}

#[derive(Serialize)]
struct KvWriteRequest<'a> {
    data: KvCredentialData<'a>,
}

#[derive(Serialize)]
struct KvCredentialData<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct KvReadResponse {
    data: KvReadData,
}

#[derive(Deserialize)]
struct KvReadData {
    data: KvReadCredentials,
}

#[derive(Deserialize)]
struct KvReadCredentials {
    username: SecretValue,
    password: SecretValue,
}

struct SecretValue(Zeroizing<String>);

impl SecretValue {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_inner(self) -> Zeroizing<String> {
        self.0
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        extract::Path,
        http::{HeaderMap, StatusCode},
        routing::{delete, get},
    };
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use url::Url;
    use zeroize::Zeroizing;

    use super::{VaultClient, VaultError};

    async fn write_secret(
        Path(path): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> StatusCode {
        if path != "valkey/target-1"
            || headers
                .get("X-Vault-Token")
                .and_then(|value| value.to_str().ok())
                != Some("synthetic-test-token")
            || body["data"]["username"] != "synthetic-user"
            || body["data"]["password"] != "synthetic-password"
        {
            return StatusCode::FORBIDDEN;
        }
        StatusCode::NO_CONTENT
    }

    async fn read_secret(
        Path(path): Path<String>,
        headers: HeaderMap,
    ) -> (StatusCode, Json<Value>) {
        if path != "valkey/target-1"
            || headers
                .get("X-Vault-Token")
                .and_then(|value| value.to_str().ok())
                != Some("synthetic-test-token")
        {
            return (StatusCode::FORBIDDEN, Json(json!({"errors": ["denied"]})));
        }
        (
            StatusCode::OK,
            Json(json!({
                "data": {"data": {"username": "synthetic-user", "password": "synthetic-password"}}
            })),
        )
    }

    async fn delete_secret(Path(path): Path<String>, headers: HeaderMap) -> StatusCode {
        if path == "valkey/target-1"
            && headers
                .get("X-Vault-Token")
                .and_then(|value| value.to_str().ok())
                == Some("synthetic-test-token")
        {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::FORBIDDEN
        }
    }

    async fn test_client() -> (VaultClient, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/v1/integration-secrets/data/{*path}",
                get(read_secret).post(write_secret),
            )
            .route(
                "/v1/integration-secrets/metadata/{*path}",
                delete(delete_secret),
            );
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let address = Url::parse(&format!(
            "http://{}/",
            listener.local_addr().expect("test listener address")
        ))
        .expect("test server URL should parse");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let client = VaultClient::new(address, Zeroizing::new("synthetic-test-token".to_owned()))
            .expect("test client should construct");
        (client, server)
    }

    #[tokio::test]
    async fn kv_v2_credentials_round_trip_and_delete_with_scoped_paths() {
        let (client, server) = test_client().await;
        client
            .write_integration_secret("valkey/target-1", "synthetic-user", "synthetic-password")
            .await
            .expect("synthetic credential should be written");
        let credentials = client
            .read_integration_secret("valkey/target-1")
            .await
            .expect("synthetic credential should be read");
        assert_eq!(credentials.username.as_str(), "synthetic-user");
        assert_eq!(credentials.password.as_str(), "synthetic-password");
        client
            .delete_integration_secret("valkey/target-1")
            .await
            .expect("synthetic credential should be deleted");
        server.abort();
    }

    #[tokio::test]
    async fn rejects_path_traversal_and_empty_credentials_before_network_access() {
        let (client, server) = test_client().await;
        assert!(matches!(
            client.read_integration_secret("../admin").await,
            Err(VaultError::InvalidSecret)
        ));
        assert!(matches!(
            client
                .write_integration_secret("valkey/target-1", "user", "")
                .await,
            Err(VaultError::InvalidSecret)
        ));
        server.abort();
    }
}
