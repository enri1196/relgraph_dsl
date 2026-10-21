-- Reverse lookup by subject for the list operations
-- (ReverseLookupSession::tuples_by_subject_page). The query fixes every
-- column below by equality and pages by `tuple_id > $after ORDER BY tuple_id`,
-- so this index serves each page as one range scan in keyset order without a
-- sort. A missing subject ID or relation is indexed as '' (no stored value is
-- empty), which keeps the nullable subject columns equality predicates.
CREATE INDEX relationship_tuples_subject_lookup_idx
    ON relgraph_authz.relationship_tuples
    (tenant, object_type, relation, subject_kind, subject_type,
     (COALESCE(subject_id, '')), (COALESCE(subject_relation, '')), tuple_id);
