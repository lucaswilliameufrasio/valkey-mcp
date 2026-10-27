ALTER TABLE mcp_transport_sessions
    ADD COLUMN server_kind TEXT NOT NULL DEFAULT 'valkey'
    CHECK (server_kind = 'valkey');
