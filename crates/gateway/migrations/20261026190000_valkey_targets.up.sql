CREATE TYPE integration_engine AS ENUM ('valkey');

CREATE TABLE integration_targets (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    engine integration_engine NOT NULL CHECK (engine = 'valkey'),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    tls_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    vault_secret_path TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID NOT NULL REFERENCES principals(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE principal_integration_grants (
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    integration_id UUID NOT NULL REFERENCES integration_targets(id) ON DELETE CASCADE,
    access_level access_level NOT NULL,
    resource_scope TEXT NOT NULL,
    granted_by UUID NOT NULL REFERENCES principals(id),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (principal_id, integration_id)
);

CREATE INDEX principal_integration_grants_integration_id_idx
    ON principal_integration_grants (integration_id);

ALTER TABLE audit_events
    ADD COLUMN integration_id UUID REFERENCES integration_targets(id) ON DELETE SET NULL,
    ADD COLUMN resource_name TEXT;

CREATE INDEX audit_events_integration_created_at_idx
    ON audit_events (integration_id, created_at DESC);
