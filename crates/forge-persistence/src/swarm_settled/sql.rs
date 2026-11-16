//! Compile-time validated static SQL definitions for sidecar-backed settlement outbox entries
//! (`DAG_SETTLED_KIND = 5` and `SWARM_SETTLED_KIND = 6`).

/// Zero-cost compile-time validated static SQL wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StaticSql(&'static str);

impl StaticSql {
    /// Construct a compile-time validated static DML/query statement.
    #[must_use]
    pub(crate) const fn dml(sql: &'static str) -> Self {
        let bytes = sql.as_bytes();
        assert!(!bytes.is_empty(), "static DML SQL must not be empty");
        let mut idx = 0;
        while idx < bytes.len() {
            let byte = bytes[idx];
            assert!(
                byte != b';',
                "static DML SQL must not contain ';' statement terminators"
            );
            assert!(
                byte != b'{' && byte != b'}',
                "static DML SQL must not contain format braces"
            );
            if idx + 1 < bytes.len() {
                assert!(
                    !(byte == b'-' && bytes[idx + 1] == b'-'),
                    "static DML SQL must not contain '--' line comments"
                );
                assert!(
                    !(byte == b'/' && bytes[idx + 1] == b'*'),
                    "static DML SQL must not contain '/*' block comments"
                );
            }
            idx += 1;
        }
        Self(sql)
    }

    /// Borrow the validated SQL statement text.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        self.0
    }
}

pub(crate) const SELECT_SETTLED_ENTRIES: StaticSql = StaticSql::dml(
    "SELECT sequence, substr(migration_id,1,17), substr(destination_id,1,17) FROM effect_fact_outbox_entries WHERE workspace_id=?1 AND fact_kind=?2 ORDER BY sequence ASC",
);

pub(crate) const SELECT_SETTLED_PAGE: StaticSql = StaticSql::dml(
    "SELECT sequence, substr(migration_id,1,17), substr(destination_id,1,17) FROM effect_fact_outbox_entries WHERE workspace_id=?1 AND fact_kind=?2 AND sequence>?3 ORDER BY sequence ASC LIMIT ?4",
);

pub(crate) const INSERT_SETTLED_ENTRY: StaticSql = StaticSql::dml(
    "INSERT INTO effect_fact_outbox_entries(migration_id,destination_id,workspace_id,fact_kind) VALUES(?1,?2,?3,?4)",
);
