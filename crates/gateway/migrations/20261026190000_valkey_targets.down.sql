DROP INDEX audit_events_integration_created_at_idx;
ALTER TABLE audit_events DROP COLUMN resource_name, DROP COLUMN integration_id;
DROP INDEX principal_integration_grants_integration_id_idx;
DROP TABLE principal_integration_grants;
DROP TABLE integration_targets;
DROP TYPE integration_engine;
