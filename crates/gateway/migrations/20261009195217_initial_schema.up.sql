CREATE TYPE access_level AS ENUM ('read', 'write');
CREATE TYPE platform_role AS ENUM ('admin', 'member');

CREATE TABLE principals (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    platform_role platform_role NOT NULL DEFAULT 'member',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (issuer, subject)
);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    operation TEXT NOT NULL,
    access_level access_level,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    error_code TEXT,
    query_fingerprint TEXT,
    database_principal TEXT,
    vault_lease_fingerprint TEXT,
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at DESC);
CREATE INDEX audit_events_principal_created_at_idx ON audit_events (principal_id, created_at DESC);
