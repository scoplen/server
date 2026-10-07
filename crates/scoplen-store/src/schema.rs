// SPDX-License-Identifier: AGPL-3.0-only
//! Logical schema checks shared by the SQLite and PostgreSQL migration tests.

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "postgres-integration")]
use sqlx::PgPool;
use sqlx::{Row, SqlitePool};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LogicalType {
    Boolean,
    Bytes,
    Integer,
    Text,
}

#[derive(Clone, Copy, Debug)]
struct ColumnSpec {
    name: &'static str,
    kind: LogicalType,
    nullable: bool,
    primary_key: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ForeignKey {
    source_column: &'static str,
    target_table: &'static str,
    target_column: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct IndexSpec {
    name: &'static str,
    columns: &'static [&'static str],
}

#[derive(Clone, Copy, Debug)]
struct TableSpec {
    name: &'static str,
    columns: &'static [ColumnSpec],
    foreign_keys: &'static [ForeignKey],
    indexes: &'static [IndexSpec],
}

const ORGANIZATIONS: TableSpec = TableSpec {
    name: "organizations",
    columns: &[
        ColumnSpec { name: "id", kind: LogicalType::Bytes, nullable: false, primary_key: true },
        ColumnSpec { name: "name", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const AUDIT_EVENTS: TableSpec = TableSpec {
    name: "audit_events",
    columns: &[
        ColumnSpec {
            name: "organization_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "sequence",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "previous_hash",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "event_bytes",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "event_hash",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "organization_id",
        target_table: "organizations",
        target_column: "id",
    }],
    indexes: &[IndexSpec {
        name: "audit_events_by_hash",
        columns: &["organization_id", "event_hash"],
    }],
};

const AUDIT_CHECKPOINTS: TableSpec = TableSpec {
    name: "audit_checkpoints",
    columns: &[
        ColumnSpec {
            name: "organization_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "sequence",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "head_hash",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "signature",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "signed_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "organization_id",
        target_table: "organizations",
        target_column: "id",
    }],
    indexes: &[],
};

const SYNC_VAULTS: TableSpec = TableSpec {
    name: "sync_vaults",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "kind", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "current_seq",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "purge_horizon",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "rotation_pending",
            kind: LogicalType::Boolean,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const SYNC_PERSONAL_VAULTS: TableSpec = TableSpec {
    name: "sync_personal_vaults",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "key_epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "wrapped_vault_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[],
};

const SYNC_VAULT_MEMBERS: TableSpec = TableSpec {
    name: "sync_vault_members",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "role", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "key_epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "wrapped_vault_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[IndexSpec {
        name: "sync_vault_members_by_account",
        columns: &["account_id", "vault_id"],
    }],
};

const SYNC_VAULT_MEMBER_KEYS: TableSpec = TableSpec {
    name: "sync_vault_member_keys",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "wrapped_vault_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[
        ForeignKey {
            source_column: "vault_id",
            target_table: "sync_vault_members",
            target_column: "vault_id",
        },
        ForeignKey {
            source_column: "account_id",
            target_table: "sync_vault_members",
            target_column: "account_id",
        },
    ],
    indexes: &[IndexSpec {
        name: "sync_vault_member_keys_by_vault_epoch",
        columns: &["vault_id", "epoch", "account_id"],
    }],
};

const SYNC_VAULT_RETIRED_EPOCHS: TableSpec = TableSpec {
    name: "sync_vault_retired_epochs",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[IndexSpec {
        name: "sync_vault_retired_epochs_by_vault",
        columns: &["vault_id", "epoch"],
    }],
};

const SYNC_OBJECTS: TableSpec = TableSpec {
    name: "sync_objects",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "object_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "sequence",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "envelope",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "tombstone",
            kind: LogicalType::Boolean,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "signer_device_id",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "key_epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "written_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[IndexSpec {
        name: "sync_objects_by_vault_sequence",
        columns: &["vault_id", "sequence"],
    }],
};

const SYNC_OBJECT_VERSIONS: TableSpec = TableSpec {
    name: "sync_object_versions",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "object_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "sequence",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "envelope",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "tombstone",
            kind: LogicalType::Boolean,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "signer_device_id",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "key_epoch",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "written_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[IndexSpec {
        name: "sync_versions_by_vault_sequence",
        columns: &["vault_id", "sequence"],
    }],
};

const SYNC_ACKS: TableSpec = TableSpec {
    name: "sync_acks",
    columns: &[
        ColumnSpec {
            name: "vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "cursor",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "acknowledged_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "vault_id",
        target_table: "sync_vaults",
        target_column: "vault_id",
    }],
    indexes: &[],
};

const ACCOUNT_KEY_BUNDLES: TableSpec = TableSpec {
    name: "sync_account_key_bundles",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "revision",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_signing_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_kem_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "recovery_blob",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "signature",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "updated_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_KEY_DEVICE_WRAPS: TableSpec = TableSpec {
    name: "sync_account_key_device_wraps",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "wrapped_ark",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "account_id",
        target_table: "sync_account_key_bundles",
        target_column: "account_id",
    }],
    indexes: &[IndexSpec {
        name: "sync_account_key_device_wraps_by_account",
        columns: &["account_id", "device_id"],
    }],
};

const ACCOUNT_KEY_CERTIFICATES: TableSpec = TableSpec {
    name: "sync_account_key_certificates",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "certificate",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "sync_account_key_certificates_by_account",
        columns: &["account_id"],
    }],
};

const ACCOUNT_KEY_REVOCATIONS: TableSpec = TableSpec {
    name: "sync_account_key_revocations",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "revocation",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "sync_account_key_revocations_by_account",
        columns: &["account_id"],
    }],
};

const JOBS: TableSpec = TableSpec {
    name: "jobs",
    columns: &[
        ColumnSpec { name: "id", kind: LogicalType::Bytes, nullable: false, primary_key: true },
        ColumnSpec { name: "kind", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "payload",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "available_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "attempts",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "lease_owner",
            kind: LogicalType::Text,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "lease_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "finished_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_error",
            kind: LogicalType::Text,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "jobs_claim_order",
        columns: &["finished_at_ms", "available_at_ms", "lease_until_ms", "created_at_ms", "id"],
    }],
};

const TABLES: &[TableSpec] = &[
    ORGANIZATIONS,
    AUDIT_EVENTS,
    AUDIT_CHECKPOINTS,
    SYNC_VAULTS,
    SYNC_PERSONAL_VAULTS,
    SYNC_VAULT_MEMBERS,
    SYNC_VAULT_MEMBER_KEYS,
    SYNC_VAULT_RETIRED_EPOCHS,
    SYNC_OBJECTS,
    SYNC_OBJECT_VERSIONS,
    SYNC_ACKS,
    ACCOUNT_KEY_BUNDLES,
    ACCOUNT_KEY_DEVICE_WRAPS,
    ACCOUNT_KEY_CERTIFICATES,
    ACCOUNT_KEY_REVOCATIONS,
    JOBS,
];

#[derive(Debug, Eq, PartialEq)]
struct ColumnShape {
    kind: LogicalType,
    nullable: bool,
    primary_key: bool,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct IndexShape {
    name: String,
    columns: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ForeignKeyShape {
    source_column: String,
    target_table: String,
    target_column: String,
}

#[derive(Debug, Eq, PartialEq)]
struct TableShape {
    columns: BTreeMap<String, ColumnShape>,
    foreign_keys: BTreeSet<ForeignKeyShape>,
    indexes: BTreeSet<IndexShape>,
}

type SchemaShape = BTreeMap<String, TableShape>;

fn sqlite_kind(table: &str, column: &str, declared: &str) -> Result<LogicalType, String> {
    let declared = declared.trim().to_ascii_uppercase();
    match (table, column, declared.as_str()) {
        ("sync_objects" | "sync_object_versions", "tombstone", "INTEGER")
        | ("sync_vaults", "rotation_pending", "INTEGER") => Ok(LogicalType::Boolean),
        (_, _, "BLOB") => Ok(LogicalType::Bytes),
        (_, _, "TEXT") => Ok(LogicalType::Text),
        (_, _, "INTEGER") => Ok(LogicalType::Integer),
        _ => Err(format!("unsupported SQLite type {declared} for {table}.{column}")),
    }
}

#[cfg(feature = "postgres-integration")]
fn postgres_kind(table: &str, column: &str, declared: &str) -> Result<LogicalType, String> {
    match (table, column, declared) {
        ("sync_objects" | "sync_object_versions", "tombstone", "boolean")
        | ("sync_vaults", "rotation_pending", "boolean") => Ok(LogicalType::Boolean),
        (_, _, "bytea") => Ok(LogicalType::Bytes),
        (_, _, "text") => Ok(LogicalType::Text),
        (_, _, "bigint") => Ok(LogicalType::Integer),
        _ => Err(format!("unsupported PostgreSQL type {declared} for {table}.{column}")),
    }
}

async fn sqlite_schema(pool: &SqlitePool) -> Result<SchemaShape, String> {
    let mut schema = BTreeMap::new();
    for table in TABLES {
        let rows = sqlx::query(
            "SELECT name, type, \"notnull\" AS not_null, pk FROM pragma_table_info(?) ORDER BY cid",
        )
        .bind(table.name)
        .fetch_all(pool)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            return Err(format!("SQLite table {} is missing", table.name));
        }
        let mut columns = BTreeMap::new();
        for row in rows {
            let name: String = row.try_get("name").map_err(|error| error.to_string())?;
            let declared: String = row.try_get("type").map_err(|error| error.to_string())?;
            let not_null: i64 = row.try_get("not_null").map_err(|error| error.to_string())?;
            let primary_key: i64 = row.try_get("pk").map_err(|error| error.to_string())?;
            let kind = sqlite_kind(table.name, &name, &declared)?;
            columns.insert(
                name,
                ColumnShape { kind, nullable: not_null == 0, primary_key: primary_key != 0 },
            );
        }
        let foreign_keys = sqlite_foreign_keys(pool, table.name).await?;
        let indexes = sqlite_indexes(pool, table.name).await?;
        schema.insert(table.name.to_owned(), TableShape { columns, foreign_keys, indexes });
    }
    Ok(schema)
}

async fn sqlite_foreign_keys(
    pool: &SqlitePool,
    table: &str,
) -> Result<BTreeSet<ForeignKeyShape>, String> {
    let rows = sqlx::query(
        "SELECT \"from\" AS source_column, \"table\" AS target_table, \"to\" AS target_column FROM pragma_foreign_key_list(?)",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| error.to_string())?;
    rows.into_iter()
        .map(|row| {
            Ok(ForeignKeyShape {
                source_column: row.try_get("source_column").map_err(|error| error.to_string())?,
                target_table: row.try_get("target_table").map_err(|error| error.to_string())?,
                target_column: row.try_get("target_column").map_err(|error| error.to_string())?,
            })
        })
        .collect()
}

async fn sqlite_indexes(pool: &SqlitePool, table: &str) -> Result<BTreeSet<IndexShape>, String> {
    let rows = sqlx::query("SELECT name FROM pragma_index_list(?) WHERE origin = 'c'")
        .bind(table)
        .fetch_all(pool)
        .await
        .map_err(|error| error.to_string())?;
    let mut indexes = BTreeSet::new();
    for row in rows {
        let name: String = row.try_get("name").map_err(|error| error.to_string())?;
        let columns = sqlx::query("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
            .bind(&name)
            .fetch_all(pool)
            .await
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|row| row.try_get("name").map_err(|error| error.to_string()))
            .collect::<Result<Vec<String>, String>>()?;
        indexes.insert(IndexShape { name, columns });
    }
    Ok(indexes)
}

#[cfg(feature = "postgres-integration")]
async fn postgres_schema(pool: &PgPool) -> Result<SchemaShape, String> {
    let mut schema = BTreeMap::new();
    for table in TABLES {
        let rows = sqlx::query(
            "SELECT column_name, data_type, is_nullable, EXISTS (SELECT 1 FROM information_schema.key_column_usage kcu JOIN information_schema.table_constraints tc ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema WHERE kcu.table_schema = c.table_schema AND kcu.table_name = c.table_name AND kcu.column_name = c.column_name AND tc.constraint_type = 'PRIMARY KEY') AS primary_key FROM information_schema.columns c WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position",
        )
        .bind(table.name)
        .fetch_all(pool)
        .await
        .map_err(|error| error.to_string())?;
        if rows.is_empty() {
            return Err(format!("PostgreSQL table {} is missing", table.name));
        }
        let mut columns = BTreeMap::new();
        for row in rows {
            let name: String = row.try_get("column_name").map_err(|error| error.to_string())?;
            let declared: String = row.try_get("data_type").map_err(|error| error.to_string())?;
            let nullable: String = row.try_get("is_nullable").map_err(|error| error.to_string())?;
            let primary_key: bool =
                row.try_get("primary_key").map_err(|error| error.to_string())?;
            let kind = postgres_kind(table.name, &name, &declared)?;
            columns.insert(name, ColumnShape { kind, nullable: nullable == "YES", primary_key });
        }
        let foreign_keys = postgres_foreign_keys(pool, table.name).await?;
        let indexes = postgres_indexes(pool, table.name).await?;
        schema.insert(table.name.to_owned(), TableShape { columns, foreign_keys, indexes });
    }
    Ok(schema)
}

#[cfg(feature = "postgres-integration")]
async fn postgres_foreign_keys(
    pool: &PgPool,
    table: &str,
) -> Result<BTreeSet<ForeignKeyShape>, String> {
    let rows = sqlx::query(
        "SELECT kcu.column_name AS source_column, ccu.table_name AS target_table, ccu.column_name AS target_column FROM information_schema.table_constraints tc JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema AND kcu.table_name = tc.table_name JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name AND ccu.constraint_schema = tc.constraint_schema WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public' AND tc.table_name = $1",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| error.to_string())?;
    rows.into_iter()
        .map(|row| {
            Ok(ForeignKeyShape {
                source_column: row.try_get("source_column").map_err(|error| error.to_string())?,
                target_table: row.try_get("target_table").map_err(|error| error.to_string())?,
                target_column: row.try_get("target_column").map_err(|error| error.to_string())?,
            })
        })
        .collect()
}

#[cfg(feature = "postgres-integration")]
async fn postgres_indexes(pool: &PgPool, table: &str) -> Result<BTreeSet<IndexShape>, String> {
    let rows = sqlx::query(
        "SELECT index_rel.relname AS name, attribute.attname AS column_name FROM pg_class table_rel JOIN pg_namespace namespace_rel ON namespace_rel.oid = table_rel.relnamespace JOIN pg_index index_data ON index_data.indrelid = table_rel.oid JOIN pg_class index_rel ON index_rel.oid = index_data.indexrelid JOIN LATERAL unnest(index_data.indkey) WITH ORDINALITY AS key_data(attnum, position) ON TRUE JOIN pg_attribute attribute ON attribute.attrelid = table_rel.oid AND attribute.attnum = key_data.attnum WHERE namespace_rel.nspname = 'public' AND table_rel.relname = $1 AND NOT index_data.indisprimary AND NOT index_data.indisunique ORDER BY index_rel.relname, key_data.position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| error.to_string())?;
    let mut indexes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in rows {
        let name: String = row.try_get("name").map_err(|error| error.to_string())?;
        let column: String = row.try_get("column_name").map_err(|error| error.to_string())?;
        indexes.entry(name).or_default().push(column);
    }
    Ok(indexes.into_iter().map(|(name, columns)| IndexShape { name, columns }).collect())
}

fn compare_schema(actual: &SchemaShape) -> Result<(), String> {
    let expected_names: BTreeSet<_> = TABLES.iter().map(|table| table.name).collect();
    let actual_names: BTreeSet<_> = actual.keys().map(String::as_str).collect();
    if expected_names != actual_names {
        return Err(format!(
            "table set differs: expected {expected_names:?}, found {actual_names:?}"
        ));
    }
    for table in TABLES {
        let actual_table =
            actual.get(table.name).ok_or_else(|| format!("table {} is missing", table.name))?;
        let expected_columns: BTreeSet<_> =
            table.columns.iter().map(|column| column.name).collect();
        let actual_columns: BTreeSet<_> = actual_table.columns.keys().map(String::as_str).collect();
        if expected_columns != actual_columns {
            return Err(format!("column set differs for {}", table.name));
        }
        for column in table.columns {
            let actual_column = actual_table
                .columns
                .get(column.name)
                .ok_or_else(|| format!("column {}.{} is missing", table.name, column.name))?;
            if actual_column.kind != column.kind
                || actual_column.nullable != column.nullable
                || actual_column.primary_key != column.primary_key
            {
                return Err(format!("column shape differs for {}.{}", table.name, column.name));
            }
        }
        let expected_foreign_keys: BTreeSet<_> = table
            .foreign_keys
            .iter()
            .map(|foreign_key| ForeignKeyShape {
                source_column: foreign_key.source_column.to_owned(),
                target_table: foreign_key.target_table.to_owned(),
                target_column: foreign_key.target_column.to_owned(),
            })
            .collect();
        if expected_foreign_keys != actual_table.foreign_keys {
            return Err(format!("foreign-key shape differs for {}", table.name));
        }
        let expected_indexes: BTreeSet<_> = table
            .indexes
            .iter()
            .map(|index| IndexShape {
                name: index.name.to_owned(),
                columns: index.columns.iter().map(|column| (*column).to_owned()).collect(),
            })
            .collect();
        if expected_indexes != actual_table.indexes {
            return Err(format!("index shape differs for {}", table.name));
        }
    }
    Ok(())
}

fn table_source<'a>(source: &'a str, table: &str) -> Result<&'a str, String> {
    let lower = source.to_ascii_lowercase();
    let marker = format!("create table {table}");
    let start = lower.find(&marker).ok_or_else(|| format!("CREATE TABLE {table} is missing"))?;
    let body_start = source[start..]
        .find('(')
        .map(|offset| start + offset + 1)
        .ok_or_else(|| format!("CREATE TABLE {table} has no body"))?;
    let body_end = source[body_start..]
        .find(");")
        .map(|offset| body_start + offset)
        .ok_or_else(|| format!("CREATE TABLE {table} has no terminator"))?;
    Ok(&source[body_start..body_end])
}

fn validate_migration_source(source: &str, postgres: bool) -> Result<(), String> {
    for table in TABLES {
        let body = table_source(source, table.name)?;
        for column in table.columns {
            let line = body
                .lines()
                .find(|line| {
                    line.trim_start().to_ascii_lowercase().starts_with(&format!("{} ", column.name))
                })
                .or_else(|| {
                    let marker = format!("alter table {} add column {}", table.name, column.name);
                    source
                        .lines()
                        .find(|line| line.trim_start().to_ascii_lowercase().starts_with(&marker))
                });
            let line =
                line.ok_or_else(|| format!("{} is missing from {}", column.name, table.name))?;
            let normalized = line.to_ascii_lowercase();
            let kind_marker = match (postgres, column.kind) {
                (true, LogicalType::Bytes) => "bytea",
                (true, LogicalType::Integer) => "bigint",
                (true, LogicalType::Boolean) => "boolean",
                (_, LogicalType::Text) => "text",
                (false, LogicalType::Bytes) => "blob",
                (false, LogicalType::Integer | LogicalType::Boolean) => "integer",
            };
            if !normalized.contains(kind_marker) {
                return Err(format!("{}.{} has the wrong type", table.name, column.name));
            }
            if !column.nullable && !normalized.contains("not null") {
                return Err(format!("{}.{} must be NOT NULL", table.name, column.name));
            }
        }
        for foreign_key in table.foreign_keys {
            let marker = format!("references {}", foreign_key.target_table);
            if !body.to_ascii_lowercase().contains(&marker) {
                return Err(format!("{} foreign key is missing", table.name));
            }
        }
        for index in table.indexes {
            if !source.to_ascii_lowercase().contains(&format!("create index {}", index.name)) {
                return Err(format!("index {} is missing", index.name));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RelationalStore, SqliteStore};
    use std::{path::PathBuf, time::Duration};

    const SQLITE_ORGANIZATIONS: &str =
        include_str!("../migrations/sqlite/20261007000000_organizations.sql");
    const SQLITE_AUDIT: &str = include_str!("../migrations/sqlite/20261008030000_audit_chain.sql");
    const SQLITE_SYNC: &str = include_str!("../migrations/sqlite/20261007010000_sync.sql");
    const SQLITE_MEMBER_REMOVAL: &str =
        include_str!("../migrations/sqlite/20261008000000_shared_vault_member_removal.sql");
    const SQLITE_PERSONAL_VAULTS: &str =
        include_str!("../migrations/sqlite/20261008010000_personal_vaults.sql");
    const SQLITE_EPOCH_RETIREMENT: &str =
        include_str!("../migrations/sqlite/20261008020000_shared_vault_epoch_retirement.sql");
    const SQLITE_KEYS: &str =
        include_str!("../migrations/sqlite/20261007020000_account_key_bundles.sql");
    const SQLITE_JOBS: &str = include_str!("../migrations/sqlite/20261007030000_jobs.sql");
    const POSTGRES_ORGANIZATIONS: &str =
        include_str!("../migrations/postgres/20261007000000_organizations.sql");
    const POSTGRES_AUDIT: &str =
        include_str!("../migrations/postgres/20261008030000_audit_chain.sql");
    const POSTGRES_SYNC: &str = include_str!("../migrations/postgres/20261007010000_sync.sql");
    const POSTGRES_MEMBER_REMOVAL: &str =
        include_str!("../migrations/postgres/20261008000000_shared_vault_member_removal.sql");
    const POSTGRES_PERSONAL_VAULTS: &str =
        include_str!("../migrations/postgres/20261008010000_personal_vaults.sql");
    const POSTGRES_EPOCH_RETIREMENT: &str =
        include_str!("../migrations/postgres/20261008020000_shared_vault_epoch_retirement.sql");
    const POSTGRES_KEYS: &str =
        include_str!("../migrations/postgres/20261007020000_account_key_bundles.sql");
    const POSTGRES_JOBS: &str = include_str!("../migrations/postgres/20261007030000_jobs.sql");

    fn test_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!("scoplen-schema-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create isolated test directory");
        path
    }

    async fn remove_test_directory(path: PathBuf) {
        for attempt in 0..20 {
            match std::fs::remove_dir_all(&path) {
                Ok(()) => return,
                Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(error) => panic!("remove test directory {}: {error}", path.display()),
            }
        }
    }

    #[test]
    fn migration_pairs_match_the_logical_schema() {
        let sqlite = [
            SQLITE_ORGANIZATIONS,
            SQLITE_AUDIT,
            SQLITE_SYNC,
            SQLITE_KEYS,
            SQLITE_JOBS,
            SQLITE_MEMBER_REMOVAL,
            SQLITE_PERSONAL_VAULTS,
            SQLITE_EPOCH_RETIREMENT,
        ];
        let postgres = [
            POSTGRES_ORGANIZATIONS,
            POSTGRES_AUDIT,
            POSTGRES_SYNC,
            POSTGRES_KEYS,
            POSTGRES_JOBS,
            POSTGRES_MEMBER_REMOVAL,
            POSTGRES_PERSONAL_VAULTS,
            POSTGRES_EPOCH_RETIREMENT,
        ];
        validate_migration_source(&sqlite.join("\n"), false)
            .expect("SQLite migration set matches schema");
        validate_migration_source(&postgres.join("\n"), true)
            .expect("PostgreSQL migration set matches schema");
    }

    #[test]
    fn migration_schema_mismatch_fails_closed() {
        let result =
            validate_migration_source("CREATE TABLE organizations (id TEXT NOT NULL);", false);
        assert!(result.is_err(), "missing migration tables must be rejected");
    }

    #[tokio::test]
    async fn postgres_connection_rejects_malformed_urls() {
        let result = crate::PostgresStore::connect("not a PostgreSQL URL").await;
        assert!(result.is_err(), "malformed PostgreSQL URLs must fail before opening a pool");
    }

    #[tokio::test]
    async fn sqlite_migrations_match_the_logical_schema() {
        let directory = test_directory();
        let store =
            SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open SQLite store");
        let schema = sqlite_schema(store.pool()).await.expect("inspect SQLite schema");
        compare_schema(&schema).expect("SQLite schema matches logical schema");
        store.pool().close().await;
        drop(store);
        remove_test_directory(directory).await;
    }

    #[cfg(feature = "postgres-integration")]
    #[tokio::test]
    async fn postgres_migrations_match_the_sqlite_logical_schema() {
        let Some(database_url) = std::env::var_os("SCOPLEN_TEST_DATABASE_URL") else {
            panic!("SCOPLEN_TEST_DATABASE_URL is required for the PostgreSQL integration test");
        };
        let database_url = database_url.to_str().expect("database URL is valid UTF-8");
        let postgres =
            crate::PostgresStore::connect(database_url).await.expect("open PostgreSQL store");
        let schema = postgres_schema(postgres.pool()).await.expect("inspect PostgreSQL schema");
        compare_schema(&schema).expect("PostgreSQL schema matches logical schema");
        postgres.ping().await.expect("PostgreSQL readiness succeeds");
        let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(postgres.pool())
            .await
            .expect("read PostgreSQL migration history");
        assert_eq!(migration_count, 6);
        postgres.pool().close().await;
        let reopened = crate::PostgresStore::connect(database_url)
            .await
            .expect("PostgreSQL migration replay is idempotent");
        let replay_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(reopened.pool())
            .await
            .expect("read replayed migration history");
        assert_eq!(replay_count, 6);

        let invalid_organization =
            sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES ($1, $2, $3)")
                .bind(vec![1_u8; 15])
                .bind("Invalid")
                .bind(0_i64)
                .execute(reopened.pool())
                .await;
        assert!(invalid_organization.is_err(), "the 16-byte organization id check must hold");
        let invalid_vault = sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES ($1, $2)")
            .bind(vec![1_u8; 16])
            .bind("unsupported")
            .execute(reopened.pool())
            .await;
        assert!(invalid_vault.is_err(), "the vault kind check must hold");
        let missing_parent = sqlx::query(
            "INSERT INTO sync_acks (vault_id, device_id, cursor, acknowledged_at_ms) VALUES ($1, $2, $3, $4)",
        )
        .bind(vec![1_u8; 16])
        .bind(vec![2_u8; 16])
        .bind(0_i64)
        .bind(0_i64)
        .execute(reopened.pool())
        .await;
        assert!(missing_parent.is_err(), "the vault foreign key must hold");
        let invalid_job = sqlx::query(
            "INSERT INTO jobs (id, kind, payload, available_at_ms, created_at_ms) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(vec![3_u8; 16])
        .bind("job")
        .bind(vec![0_u8; 1_048_577])
        .bind(0_i64)
        .bind(0_i64)
        .execute(reopened.pool())
        .await;
        assert!(invalid_job.is_err(), "the job payload limit must hold");

        let organization = uuid::Uuid::new_v4().into_bytes();
        sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES ($1, $2, $3)")
            .bind(organization.as_slice())
            .bind("PostgreSQL parity")
            .bind(1_i64)
            .execute(reopened.pool())
            .await
            .expect("insert PostgreSQL audit organization");
        let audit = reopened
            .append_audit_event(organization, b"postgres event", 1)
            .await
            .expect("append PostgreSQL audit event");
        assert_eq!(
            reopened.verify_audit_chain(organization).await.expect("verify audit"),
            audit.event_hash
        );
        let checkpoint = crate::AuditCheckpoint {
            organization_id: organization,
            sequence: audit.sequence,
            head_hash: audit.event_hash,
            signature: [4; 64],
            signed_at_ms: 2,
        };
        reopened.write_audit_checkpoint(&checkpoint).await.expect("write PostgreSQL checkpoint");
        let job_id = uuid::Uuid::new_v4().into_bytes();
        reopened
            .enqueue_job(job_id, "postgres-parity", b"payload", 0)
            .await
            .expect("enqueue PostgreSQL job");
        let claimed = reopened
            .claim_job("postgres-worker", 1, 1_000)
            .await
            .expect("claim PostgreSQL job")
            .expect("PostgreSQL job is available");
        assert_eq!(claimed.id, job_id);
        reopened.complete_job(job_id, "postgres-worker", 2).await.expect("complete PostgreSQL job");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(organization.as_slice())
            .execute(reopened.pool())
            .await
            .expect("clean PostgreSQL parity organization");
        reopened.pool().close().await;
    }
}
