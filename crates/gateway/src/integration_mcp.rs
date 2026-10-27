use std::time::Duration;

use async_nats::jetstream;
use bytes::Bytes;
use futures_util::TryStreamExt;
use serde_json::{Map, Value, json};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{
    auth::AuthenticatedPrincipal, domain::AccessLevel, integrations::IntegrationEngine,
    state::AppState,
};

const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

#[derive(FromRow)]
struct TargetGrant {
    id: Uuid,
    host: String,
    port: i32,
    tls_enabled: bool,
    vault_secret_path: String,
    access_level: AccessLevel,
    resource_scope: String,
}

pub(crate) fn initialize_result(server_kind: &str, params: &Value) -> Value {
    let requested_version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("2026-07-28");
    let protocol_version = if crate::protocol::supported_protocol_version(requested_version) {
        requested_version
    } else {
        "2026-07-28"
    };
    json!({
        "protocolVersion": protocol_version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": format!("{server_kind}-mcp"), "version": env!("CARGO_PKG_VERSION")},
        "instructions": if server_kind == "nats" {
            "Acesse somente conexões e subjects autorizados. Publicações têm efeito externo e não são repetidas automaticamente."
        } else {
            "Acesse somente conexões e prefixos autorizados. Alterações e exclusões exigem grant de escrita."
        }
    })
}

pub(crate) async fn dispatch_request(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    server_kind: &str,
    request: Map<String, Value>,
) -> Result<Value, (i64, &'static str)> {
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err((-32600, "Invalid Request"));
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or((-32600, "Invalid Request"))?;
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    match method {
        "initialize" => Ok(initialize_result(server_kind, &params)),
        "notifications/initialized" | "notifications/cancelled" => Ok(Value::Null),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_definitions(server_kind)})),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or((-32602, "Invalid params"))?;
            let arguments = params
                .get("arguments")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            match call_tool(state, actor, server_kind, name, arguments).await {
                Ok(result) => Ok(json!({
                    "content": [{"type": "text", "text": result.to_string()}],
                    "structuredContent": result,
                    "isError": false
                })),
                Err(message) => Ok(json!({
                    "content": [{"type": "text", "text": message}],
                    "isError": true
                })),
            }
        }
        _ => Err((-32601, "Method not found")),
    }
}

fn tool_definitions(server_kind: &str) -> Vec<Value> {
    if server_kind == "nats" {
        return vec![
            json!({"name":"list_nats_connections","description":"Lista conexões NATS autorizadas.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}),
            json!({"name":"list_streams","description":"Lista até 100 streams JetStream que contenham subjects no prefixo autorizado.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"}},"required":["integration_id"],"additionalProperties":false}}),
            json!({"name":"read_stream_message","description":"Lê uma mensagem JetStream por stream e sequência, limitada a 16 KiB.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"stream":{"type":"string","minLength":1,"maxLength":128},"sequence":{"type":"integer","minimum":1}},"required":["integration_id","stream","sequence"],"additionalProperties":false}}),
            json!({"name":"publish_message","description":"Publica uma mensagem em subject autorizado. A chamada não é repetida automaticamente.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"subject":{"type":"string","minLength":1,"maxLength":256},"payload":{"type":"string","maxLength":16384}},"required":["integration_id","subject","payload"],"additionalProperties":false}}),
            json!({"name":"delete_stream_message","description":"Exclui uma mensagem específica de um stream autorizado usando sua sequência. A exclusão é permanente.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"stream":{"type":"string","minLength":1,"maxLength":128},"sequence":{"type":"integer","minimum":1}},"required":["integration_id","stream","sequence"],"additionalProperties":false}}),
        ];
    }

    vec![
        json!({"name":"list_valkey_connections","description":"Lista conexões Valkey autorizadas.","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}),
        json!({"name":"list_keys","description":"Lista chaves por prefixo autorizado usando SCAN, com cursor e limite.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"cursor":{"type":"integer","minimum":0},"count":{"type":"integer","minimum":1,"maximum":100}},"required":["integration_id"],"additionalProperties":false}}),
        json!({"name":"get_key","description":"Obtém valor string e TTL de uma chave no prefixo autorizado.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"key":{"type":"string","minLength":1,"maxLength":512}},"required":["integration_id","key"],"additionalProperties":false}}),
        json!({"name":"set_key","description":"Define uma chave string com TTL obrigatório de até 24 horas.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"key":{"type":"string","minLength":1,"maxLength":512},"value":{"type":"string","maxLength":16384},"ttl_seconds":{"type":"integer","minimum":1,"maximum":86400}},"required":["integration_id","key","value","ttl_seconds"],"additionalProperties":false}}),
        json!({"name":"delete_key","description":"Remove uma chave explícita dentro do prefixo autorizado.","inputSchema":{"type":"object","properties":{"integration_id":{"type":"string","format":"uuid"},"key":{"type":"string","minLength":1,"maxLength":512}},"required":["integration_id","key"],"additionalProperties":false}}),
    ]
}

async fn call_tool(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    server_kind: &str,
    tool: &str,
    arguments: Map<String, Value>,
) -> Result<Value, &'static str> {
    let engine = if server_kind == "nats" {
        IntegrationEngine::Nats
    } else {
        IntegrationEngine::Valkey
    };
    let known_tool = match engine {
        IntegrationEngine::Nats => matches!(
            tool,
            "list_nats_connections"
                | "list_streams"
                | "read_stream_message"
                | "publish_message"
                | "delete_stream_message"
        ),
        IntegrationEngine::Valkey => matches!(
            tool,
            "list_valkey_connections" | "list_keys" | "get_key" | "set_key" | "delete_key"
        ),
    };
    if !known_tool {
        return Err("Ferramenta incompatível com este servidor MCP.");
    }
    if tool == "list_nats_connections" || tool == "list_valkey_connections" {
        return list_connections(state, actor, engine).await;
    }

    let target_id = required_uuid(&arguments, "integration_id")?;
    let target = load_target_grant(state, actor, target_id, engine).await?;
    let write = matches!(
        tool,
        "publish_message" | "delete_stream_message" | "set_key" | "delete_key"
    );
    if write && !target.access_level.allows(AccessLevel::Write) {
        audit(state, actor, &target, tool, "denied", None).await;
        return Err("Acesso de escrita não foi concedido.");
    }
    let secret = match state
        .vault_runtime
        .read_integration_secret(&target.vault_secret_path)
        .await
    {
        Ok(secret) => secret,
        Err(_) => {
            audit(
                state,
                actor,
                &target,
                tool,
                "failure",
                arguments.get("key").and_then(Value::as_str),
            )
            .await;
            return Err("A credencial da conexão não está disponível.");
        }
    };

    let operation = async {
        match engine {
            IntegrationEngine::Valkey => {
                valkey_operation(
                    state,
                    actor,
                    &target,
                    tool,
                    &arguments,
                    &secret.username,
                    &secret.password,
                )
                .await
            }
            IntegrationEngine::Nats => {
                nats_operation(
                    state,
                    actor,
                    &target,
                    tool,
                    &arguments,
                    &secret.username,
                    &secret.password,
                )
                .await
            }
        }
    };
    let result = match tokio::time::timeout(Duration::from_secs(15), operation).await {
        Ok(result) => result,
        Err(_) if write => Err(
            "A operação expirou; o resultado pode ser incerto. Verifique o estado antes de repetir.",
        ),
        Err(_) => Err("A operação excedeu o limite de tempo."),
    };
    if result.is_err() {
        let resource_name = arguments
            .get("key")
            .or_else(|| arguments.get("subject"))
            .or_else(|| arguments.get("stream"))
            .and_then(Value::as_str);
        let outcome = match &result {
            Err(message)
                if message.contains("fora do prefixo autorizado")
                    || message.contains("fora do escopo autorizado") =>
            {
                "denied"
            }
            _ => "failure",
        };
        audit(state, actor, &target, tool, outcome, resource_name).await;
    }
    result
}

async fn list_connections(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    engine: IntegrationEngine,
) -> Result<Value, &'static str> {
    let rows = sqlx::query_as::<_, (Uuid, String, AccessLevel, String)>(
        "SELECT t.id, t.name, g.access_level, g.resource_scope \
         FROM integration_targets t JOIN principal_integration_grants g ON g.integration_id = t.id \
         WHERE t.enabled = TRUE AND t.engine = $1 AND g.principal_id = $2 ORDER BY t.name",
    )
    .bind(engine)
    .bind(actor.0.id)
    .fetch_all(&state.control_pool)
    .await
    .map_err(|_| "Não foi possível listar as conexões autorizadas.")?;
    Ok(Value::Array(
        rows.into_iter()
            .map(|(id, name, level, scope)| {
                json!({"id":id,"name":name,"access_level":level,"resource_scope":scope})
            })
            .collect(),
    ))
}

async fn load_target_grant(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    target_id: Uuid,
    engine: IntegrationEngine,
) -> Result<TargetGrant, &'static str> {
    sqlx::query_as::<_, TargetGrant>(
        "SELECT t.id, t.host, t.port, t.tls_enabled, \
                t.vault_secret_path, g.access_level, g.resource_scope \
         FROM integration_targets t JOIN principal_integration_grants g ON g.integration_id = t.id \
         WHERE t.id = $1 AND t.engine = $2 AND t.enabled = TRUE \
           AND g.principal_id = $3",
    )
    .bind(target_id)
    .bind(engine)
    .bind(actor.0.id)
    .fetch_optional(&state.control_pool)
    .await
    .map_err(|_| "Não foi possível verificar a autorização.")?
    .ok_or("Acesso a esta conexão não foi concedido.")
}

async fn valkey_operation(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    target: &TargetGrant,
    tool: &str,
    arguments: &Map<String, Value>,
    username: &str,
    password: &str,
) -> Result<Value, &'static str> {
    let key = arguments
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !key.is_empty() && (key.len() > 512 || !key.starts_with(&target.resource_scope)) {
        return Err("A chave está fora do prefixo autorizado.");
    }
    let mut url = url::Url::parse(&format!(
        "{}://{}:{}/",
        if target.tls_enabled {
            "rediss"
        } else {
            "redis"
        },
        endpoint_host(&target.host),
        target.port
    ))
    .map_err(|_| "A conexão Valkey está inválida.")?;
    if !username.is_empty() {
        url.set_username(username)
            .map_err(|_| "A conexão Valkey está inválida.")?;
    }
    url.set_password(Some(password))
        .map_err(|_| "A conexão Valkey está inválida.")?;
    let client =
        redis::Client::open(url.as_str()).map_err(|_| "A conexão Valkey está inválida.")?;
    let mut connection = tokio::time::timeout(
        Duration::from_secs(5),
        client.get_multiplexed_async_connection(),
    )
    .await
    .map_err(|_| "A operação Valkey excedeu o limite de tempo.")?
    .map_err(|_| "Não foi possível conectar ao Valkey.")?;

    let effect = match tool {
        "list_keys" => {
            let cursor = arguments.get("cursor").and_then(Value::as_u64).unwrap_or(0);
            let count = arguments
                .get("count")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .clamp(1, 100);
            let pattern = format!("{}*", target.resource_scope);
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(count)
                .query_async(&mut connection)
                .await
                .map_err(|_| "Não foi possível listar chaves Valkey.")?;
            let bounded_keys = keys
                .into_iter()
                .filter(|candidate| candidate.starts_with(&target.resource_scope))
                .take(100)
                .collect::<Vec<_>>();
            json!({"cursor":next_cursor,"keys":bounded_keys})
        }
        "get_key" => {
            if key.is_empty() {
                return Err("O campo key é obrigatório.");
            }
            let key_type: String = redis::cmd("TYPE")
                .arg(key)
                .query_async(&mut connection)
                .await
                .map_err(|_| "Não foi possível consultar a chave Valkey.")?;
            let ttl: i64 = redis::cmd("TTL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .map_err(|_| "Não foi possível consultar o TTL Valkey.")?;
            if key_type != "string" {
                json!({"type":key_type,"ttl_seconds":ttl,"value":null})
            } else {
                let value: Option<String> = redis::cmd("GET")
                    .arg(key)
                    .query_async(&mut connection)
                    .await
                    .map_err(|_| "Não foi possível ler a chave Valkey.")?;
                let value = value.unwrap_or_default();
                if value.len() > MAX_PAYLOAD_BYTES {
                    return Err("O valor excede o limite de resposta de 16 KiB.");
                }
                json!({"type":key_type,"ttl_seconds":ttl,"value":value})
            }
        }
        "set_key" => {
            let value = arguments
                .get("value")
                .and_then(Value::as_str)
                .ok_or("O campo value é obrigatório.")?;
            let ttl = arguments
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .filter(|ttl| (1..=86_400).contains(ttl))
                .ok_or("O TTL deve estar entre 1 segundo e 24 horas.")?;
            if key.is_empty() || value.len() > MAX_PAYLOAD_BYTES {
                return Err("A chave ou o valor está fora dos limites permitidos.");
            }
            let _: String = redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(ttl)
                .query_async(&mut connection)
                .await
                .map_err(|_| "Não foi possível gravar a chave Valkey.")?;
            json!({"updated":true,"ttl_seconds":ttl})
        }
        "delete_key" => {
            if key.is_empty() {
                return Err("O campo key é obrigatório.");
            }
            let removed: u64 = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut connection)
                .await
                .map_err(|_| "Não foi possível remover a chave Valkey.")?;
            json!({"removed":removed == 1})
        }
        _ => return Err("Ferramenta Valkey desconhecida."),
    };
    audit(
        state,
        actor,
        target,
        tool,
        "success",
        (!key.is_empty()).then_some(key),
    )
    .await;
    Ok(effect)
}

async fn nats_operation(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    target: &TargetGrant,
    tool: &str,
    arguments: &Map<String, Value>,
    username: &str,
    password: &str,
) -> Result<Value, &'static str> {
    let address = format!("nats://{}:{}", endpoint_host(&target.host), target.port);
    let options = if username.is_empty() {
        async_nats::ConnectOptions::with_token(password.to_owned())
    } else {
        async_nats::ConnectOptions::with_user_and_password(username.to_owned(), password.to_owned())
    }
    .require_tls(target.tls_enabled);
    let client = tokio::time::timeout(Duration::from_secs(5), options.connect(address))
        .await
        .map_err(|_| "A conexão NATS excedeu o limite de tempo.")?
        .map_err(|_| "Não foi possível conectar ao NATS.")?;

    match tool {
        "list_streams" => {
            let context = jetstream::new(client);
            let mut names = context.stream_names();
            let mut streams = Vec::new();
            let mut examined = 0;
            while streams.len() < 100 && examined < 200 {
                let name = match names
                    .try_next()
                    .await
                    .map_err(|_| "Não foi possível listar streams NATS.")?
                {
                    Some(name) => name,
                    None => break,
                };
                examined += 1;
                let Ok(mut stream) = context.get_stream(name.as_str()).await else {
                    continue;
                };
                let Ok(info) = stream.info().await else {
                    continue;
                };
                if info
                    .config
                    .subjects
                    .iter()
                    .any(|subject| subject.starts_with(&target.resource_scope))
                {
                    streams.push(json!({
                        "name": name,
                        "messages": info.state.messages,
                        "first_sequence": info.state.first_sequence,
                        "last_sequence": info.state.last_sequence
                    }));
                }
            }
            audit(state, actor, target, tool, "success", None).await;
            let truncated = streams.len() == 100;
            Ok(json!({"streams":streams,"truncated":truncated}))
        }
        "read_stream_message" | "delete_stream_message" => {
            let stream_name = arguments
                .get("stream")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let sequence = arguments
                .get("sequence")
                .and_then(Value::as_u64)
                .ok_or("A sequência é obrigatória.")?;
            if stream_name.is_empty()
                || stream_name.len() > 128
                || sequence == 0
                || !stream_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            {
                return Err("O nome do stream é inválido.");
            }
            let context = jetstream::new(client);
            let mut stream = context
                .get_stream(stream_name)
                .await
                .map_err(|_| "O stream não existe ou não está autorizado.")?;
            let info = stream
                .info()
                .await
                .map_err(|_| "Não foi possível inspecionar o stream.")?;
            if !info
                .config
                .subjects
                .iter()
                .any(|subject| subject.starts_with(&target.resource_scope))
            {
                return Err("O stream está fora do escopo autorizado.");
            }
            if tool == "delete_stream_message" {
                let deleted = stream
                    .delete_message(sequence)
                    .await
                    .map_err(|_| "Não foi possível excluir a mensagem do stream.")?;
                let resource = format!("{stream_name}/{sequence}");
                audit(state, actor, target, tool, "success", Some(&resource)).await;
                return Ok(json!({"deleted":deleted,"stream":stream_name,"sequence":sequence}));
            }
            let message = stream
                .get_raw_message(sequence)
                .await
                .map_err(|_| "A mensagem não existe ou não está acessível.")?;
            if message.payload.len() > MAX_PAYLOAD_BYTES {
                return Err("A mensagem excede o limite de resposta de 16 KiB.");
            }
            let payload = String::from_utf8_lossy(&message.payload).into_owned();
            let subject = message.subject.to_string();
            audit(state, actor, target, tool, "success", Some(&subject)).await;
            Ok(
                json!({"stream":stream_name,"sequence":message.sequence,"subject":message.subject,"payload":payload,"time":message.time.to_string()}),
            )
        }
        "publish_message" => {
            let subject = arguments
                .get("subject")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let payload = arguments
                .get("payload")
                .and_then(Value::as_str)
                .ok_or("O payload é obrigatório.")?;
            if !valid_nats_subject(subject) || !subject.starts_with(&target.resource_scope) {
                return Err("O subject está fora do escopo autorizado.");
            }
            if payload.len() > MAX_PAYLOAD_BYTES {
                return Err("O payload excede o limite de 16 KiB.");
            }
            tokio::time::timeout(
                Duration::from_secs(5),
                client.publish(
                    subject.to_owned(),
                    Bytes::copy_from_slice(payload.as_bytes()),
                ),
            )
            .await
            .map_err(|_| "A publicação NATS excedeu o limite de tempo.")?
            .map_err(|_| "Não foi possível publicar no NATS.")?;
            client
                .flush()
                .await
                .map_err(|_| "A publicação NATS teve resultado incerto.")?;
            audit(state, actor, target, tool, "success", Some(subject)).await;
            Ok(json!({"published":true,"subject":subject}))
        }
        _ => Err("Ferramenta NATS desconhecida."),
    }
}

async fn audit(
    state: &AppState,
    actor: &AuthenticatedPrincipal,
    target: &TargetGrant,
    operation: &str,
    outcome: &str,
    resource: Option<&str>,
) {
    let resource_name = resource.map(|value| value.chars().take(256).collect::<String>());
    let _ = sqlx::query(
        "INSERT INTO audit_events \
         (id, principal_id, issuer, subject, integration_id, resource_name, operation, outcome) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(actor.0.id)
    .bind(&actor.0.issuer)
    .bind(&actor.0.subject)
    .bind(target.id)
    .bind(resource_name)
    .bind(operation)
    .bind(outcome)
    .execute(&state.control_pool)
    .await;
}

fn required_uuid(arguments: &Map<String, Value>, field: &str) -> Result<Uuid, &'static str> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or("O identificador da conexão é obrigatório.")?
        .parse()
        .map_err(|_| "O identificador da conexão é inválido.")
}

fn endpoint_host(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

fn valid_nats_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= 256
        && subject.split('.').all(|token| {
            !token.is_empty()
                && token.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
        })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::tool_definitions;

    #[test]
    fn nats_and_valkey_tool_catalogs_are_distinct_and_never_accept_credentials() {
        let nats = tool_definitions("nats");
        let valkey = tool_definitions("valkey");
        let nats_names = nats
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        let valkey_names = valkey
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect::<Vec<_>>();
        assert!(nats_names.contains(&"read_stream_message"));
        assert!(nats_names.contains(&"publish_message"));
        assert!(nats_names.contains(&"delete_stream_message"));
        assert!(valkey_names.contains(&"get_key"));
        assert!(valkey_names.contains(&"set_key"));
        assert!(valkey_names.contains(&"delete_key"));

        for tool in nats.iter().chain(valkey.iter()) {
            assert_schema_has_no_credentials(&tool["inputSchema"]);
            assert!(tool["inputSchema"]["properties"]["host"].is_null());
            assert!(tool["inputSchema"]["properties"]["password"].is_null());
        }
    }

    fn assert_schema_has_no_credentials(schema: &Value) {
        let properties = schema["properties"]
            .as_object()
            .expect("tool schema should define properties");
        assert!(!properties.contains_key("username"));
        assert!(!properties.contains_key("password"));
        assert!(!properties.contains_key("connection_string"));
    }

    #[test]
    fn nats_publish_subjects_are_concrete_and_bounded() {
        assert!(super::valid_nats_subject("orders.created"));
        assert!(!super::valid_nats_subject("orders.*"));
        assert!(!super::valid_nats_subject("orders..created"));
        assert!(!super::valid_nats_subject("orders.created subject"));
        assert!(!super::valid_nats_subject(&"a".repeat(257)));
    }
}
