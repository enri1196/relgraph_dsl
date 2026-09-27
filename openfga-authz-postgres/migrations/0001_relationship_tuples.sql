CREATE SCHEMA IF NOT EXISTS openfga_authz;

CREATE TABLE openfga_authz.relationship_tuples (
    tuple_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant TEXT COLLATE "C" NOT NULL
        CHECK (octet_length(tenant) BETWEEN 1 AND 128),
    object_type TEXT COLLATE "C" NOT NULL
        CHECK (octet_length(object_type) BETWEEN 1 AND 128),
    object_id TEXT COLLATE "C" NOT NULL
        CHECK (octet_length(object_id) BETWEEN 1 AND 256),
    relation TEXT COLLATE "C" NOT NULL
        CHECK (octet_length(relation) BETWEEN 1 AND 128),
    subject_kind TEXT COLLATE "C" NOT NULL
        CHECK (subject_kind IN ('direct', 'userset', 'typed_wildcard')),
    subject_type TEXT COLLATE "C" NOT NULL
        CHECK (octet_length(subject_type) BETWEEN 1 AND 128),
    subject_id TEXT COLLATE "C"
        CHECK (subject_id IS NULL OR octet_length(subject_id) BETWEEN 1 AND 256),
    subject_relation TEXT COLLATE "C"
        CHECK (subject_relation IS NULL OR octet_length(subject_relation) BETWEEN 1 AND 128),
    condition_name TEXT COLLATE "C"
        CHECK (condition_name IS NULL OR octet_length(condition_name) BETWEEN 1 AND 128),
    context_json TEXT,
    identity_digest BYTEA NOT NULL
        CHECK (octet_length(identity_digest) = 32),
    CONSTRAINT relationship_tuples_subject_shape CHECK (
        (subject_kind = 'direct' AND subject_id IS NOT NULL AND subject_relation IS NULL)
        OR (subject_kind = 'userset' AND subject_id IS NOT NULL AND subject_relation IS NOT NULL)
        OR (subject_kind = 'typed_wildcard' AND subject_id IS NULL AND subject_relation IS NULL)
    ),
    CONSTRAINT relationship_tuples_condition_pair CHECK (
        (condition_name IS NULL AND context_json IS NULL)
        OR (condition_name IS NOT NULL AND context_json IS NOT NULL)
    ),
    CONSTRAINT relationship_tuples_identity_digest_key UNIQUE (identity_digest)
);

CREATE INDEX relationship_tuples_lookup_idx
    ON openfga_authz.relationship_tuples
    (tenant, object_type, object_id, relation, tuple_id);
