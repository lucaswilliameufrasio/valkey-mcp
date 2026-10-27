export type PlatformRole = 'admin' | 'member';
export type AccessLevel = 'read' | 'write';
export type IntegrationEngine = 'valkey';

export interface Principal {
  id: string;
  issuer: string;
  subject: string;
  email?: string;
  display_name?: string;
  platform_role: PlatformRole;
  enabled: boolean;
  last_seen_at?: string;
}

export interface MeResponse {
  principal: Principal;
}

export interface IntegrationTarget {
  id: string;
  name: string;
  engine: IntegrationEngine;
  host: string;
  port: number;
  tls_enabled: boolean;
  enabled: boolean;
  created_at: string;
}

export interface AuditEvent {
  id: string;
  principal_id?: string;
  issuer: string;
  subject: string;
  integration_id?: string;
  integration_name?: string;
  integration_engine?: IntegrationEngine;
  resource_name?: string;
  operation: string;
  access_level?: AccessLevel;
  outcome: 'success' | 'denied' | 'failure';
  error_code?: string;
  query_fingerprint?: string;
  database_principal?: string;
  vault_lease_fingerprint?: string;
  duration_ms?: number;
  created_at: string;
}

export interface AuthConfig {
  issuer: string;
  client_id: string;
  resource: string;
  scopes: string[];
  mcp_endpoint: string;
  oauth_authorization_metadata_url: string;
}
