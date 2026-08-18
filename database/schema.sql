BEGIN;

-- Trustee maps each logical store to a table named after its namespace.
-- Keep these definitions aligned with deps/key-value-storage/src/postgres/set-up.sql.
CREATE TABLE IF NOT EXISTS kbs (
    value BYTEA,
    key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS repository (
    value BYTEA,
    key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS attestation_service_policy (
    value BYTEA,
    key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS reference_value (
    value BYTEA,
    key TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS kbs_protocol_session (
    value BYTEA,
    key TEXT PRIMARY KEY
);

COMMIT;
