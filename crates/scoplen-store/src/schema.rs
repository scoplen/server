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

const DEPLOYMENT_AUDIT_EVENTS: TableSpec = TableSpec {
    name: "deployment_audit_events",
    columns: &[
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
    foreign_keys: &[],
    indexes: &[],
};

const DEPLOYMENT_AUDIT_CHECKPOINTS: TableSpec = TableSpec {
    name: "deployment_audit_checkpoints",
    columns: &[
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
    foreign_keys: &[],
    indexes: &[],
};

const DEVICE_ACCESS_TOKEN_KEYS: TableSpec = TableSpec {
    name: "device_access_token_keys",
    columns: &[
        ColumnSpec { name: "kid", kind: LogicalType::Text, nullable: false, primary_key: true },
        ColumnSpec {
            name: "public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "encrypted_seed",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "activated_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "retired_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "verify_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "active_slot",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "device_access_token_keys_one_active",
        columns: &["active_slot"],
    }],
};

const OPERATOR_ACCESS_TOKEN_KEYS: TableSpec = TableSpec {
    name: "operator_access_token_keys",
    columns: &[
        ColumnSpec { name: "kid", kind: LogicalType::Text, nullable: false, primary_key: true },
        ColumnSpec {
            name: "public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "encrypted_seed",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "activated_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "retired_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "verify_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "active_slot",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "operator_access_token_keys_one_active",
        columns: &["active_slot"],
    }],
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
        ColumnSpec {
            name: "accepted_put_cbor",
            kind: LogicalType::Bytes,
            nullable: true,
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
    indexes: &[
        IndexSpec {
            name: "sync_account_key_device_wraps_by_account",
            columns: &["account_id", "device_id"],
        },
        IndexSpec { name: "sync_account_key_device_wraps_by_device", columns: &["device_id"] },
    ],
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

const IDENTITY_ACCOUNTS: TableSpec = TableSpec {
    name: "identity_accounts",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "email", kind: LogicalType::Text, nullable: true, primary_key: false },
        ColumnSpec {
            name: "password_owned",
            kind: LogicalType::Boolean,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_signing_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_kem_public_key",
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
    foreign_keys: &[],
    indexes: &[],
};

const IDENTITY_DEVICES: TableSpec = TableSpec {
    name: "identity_devices",
    columns: &[
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "certificate",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "active",
            kind: LogicalType::Boolean,
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
        source_column: "account_id",
        target_table: "identity_accounts",
        target_column: "account_id",
    }],
    indexes: &[IndexSpec {
        name: "identity_devices_by_account",
        columns: &["account_id", "device_id"],
    }],
};

const PERSONAL_INVITATIONS: TableSpec = TableSpec {
    name: "personal_invitations",
    columns: &[
        ColumnSpec {
            name: "invitation_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "token_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issuer_operator_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issued_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "consumed_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "consumed_account_id",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "consumed_account_id",
        target_table: "identity_accounts",
        target_column: "account_id",
    }],
    indexes: &[IndexSpec { name: "personal_invitations_by_expiry", columns: &["expires_at_ms"] }],
};

const PERSONAL_ADMISSION: TableSpec = TableSpec {
    name: "personal_admission",
    columns: &[
        ColumnSpec { name: "kind", kind: LogicalType::Integer, nullable: false, primary_key: true },
        ColumnSpec {
            name: "bucket_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "window_start_ms",
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
            name: "failure_streak",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_failure_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "cooldown_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "personal_admission_by_retention",
        columns: &["retain_until_ms"],
    }],
};

const PERSONAL_INVITATION_ADMISSION: TableSpec = TableSpec {
    name: "personal_invitation_admission",
    columns: &[
        ColumnSpec { name: "kind", kind: LogicalType::Integer, nullable: false, primary_key: true },
        ColumnSpec {
            name: "bucket_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "window_start_ms",
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
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "personal_invitation_admission_by_retention",
        columns: &["retain_until_ms"],
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

const DEVICE_AUTH_CHALLENGES: TableSpec = TableSpec {
    name: "device_auth_challenges",
    columns: &[
        ColumnSpec {
            name: "nonce_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issued_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "consumed_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec { name: "device_auth_challenges_by_expiry", columns: &["expires_at_ms"] }],
};

const DEVICE_REFRESH_FAMILIES: TableSpec = TableSpec {
    name: "device_refresh_families",
    columns: &[
        ColumnSpec {
            name: "family_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "dpop_jkt",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "audience",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "scope", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "revoked_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[
        ForeignKey {
            source_column: "account_id",
            target_table: "identity_accounts",
            target_column: "account_id",
        },
        ForeignKey {
            source_column: "device_id",
            target_table: "identity_devices",
            target_column: "device_id",
        },
    ],
    indexes: &[
        IndexSpec { name: "device_refresh_families_by_expiry", columns: &["expires_at_ms"] },
        IndexSpec {
            name: "device_refresh_families_by_device",
            columns: &["device_id", "expires_at_ms"],
        },
    ],
};

const DEVICE_REFRESH_TOKENS: TableSpec = TableSpec {
    name: "device_refresh_tokens",
    columns: &[
        ColumnSpec {
            name: "token_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "family_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issued_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "spent_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "family_id",
        target_table: "device_refresh_families",
        target_column: "family_id",
    }],
    indexes: &[
        IndexSpec { name: "device_refresh_tokens_one_live", columns: &["family_id"] },
        IndexSpec {
            name: "device_refresh_tokens_by_family",
            columns: &["family_id", "issued_at_ms"],
        },
    ],
};

const DEVICE_DPOP_REPLAYS: TableSpec = TableSpec {
    name: "device_dpop_replays",
    columns: &[
        ColumnSpec {
            name: "dpop_jkt",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "jti_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "device_dpop_replays_by_retention",
        columns: &["retain_until_ms"],
    }],
};

const DEVICE_AUTH_ADMISSION: TableSpec = TableSpec {
    name: "device_auth_admission",
    columns: &[
        ColumnSpec {
            name: "endpoint",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "kind", kind: LogicalType::Integer, nullable: false, primary_key: true },
        ColumnSpec {
            name: "bucket_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "window_start_ms",
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
            name: "failure_streak",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_failure_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "cooldown_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "device_auth_admission_by_retention",
        columns: &["retain_until_ms"],
    }],
};

const OPERATOR_AUTH_ADMISSION: TableSpec = TableSpec {
    name: "operator_auth_admission",
    columns: DEVICE_AUTH_ADMISSION.columns,
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "operator_auth_admission_by_retention",
        columns: &["retain_until_ms"],
    }],
};

const OPERATOR_DPOP_REPLAYS: TableSpec = TableSpec {
    name: "operator_dpop_replays",
    columns: DEVICE_DPOP_REPLAYS.columns,
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "operator_dpop_replays_by_retention",
        columns: &["retain_until_ms"],
    }],
};

const DEPLOYMENT_OPERATORS: TableSpec = TableSpec {
    name: "deployment_operators",
    columns: &[
        ColumnSpec {
            name: "operator_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "active",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "created_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const OPERATOR_CREDENTIALS: TableSpec = TableSpec {
    name: "operator_credentials",
    columns: &[
        ColumnSpec {
            name: "credential_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "operator_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "user_handle",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "rp_id", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "credential_version",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "credential_state",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "active",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "created_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "operator_id",
        target_table: "deployment_operators",
        target_column: "operator_id",
    }],
    indexes: &[],
};

const OPERATOR_SETUP: TableSpec = TableSpec {
    name: "operator_setup",
    columns: &[
        ColumnSpec {
            name: "singleton",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "token_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issued_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "completed_at_s",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const OPERATOR_CEREMONIES: TableSpec = TableSpec {
    name: "operator_ceremonies",
    columns: &[
        ColumnSpec {
            name: "ceremony_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "purpose",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "operator_id",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "setup_digest",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "browser_jkt",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "rp_id", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "issued_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_s",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "state_version",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "library_state",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "consumed_at_s",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec { name: "operator_ceremonies_by_expiry", columns: &["expires_at_s"] }],
};

const OPERATOR_REFRESH_FAMILIES: TableSpec = TableSpec {
    name: "operator_refresh_families",
    columns: &[
        ColumnSpec {
            name: "family_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "principal_kind",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "operator_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "credential_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "dpop_jkt",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "audience",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "scope", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "revoked_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[
        ForeignKey {
            source_column: "operator_id",
            target_table: "deployment_operators",
            target_column: "operator_id",
        },
        ForeignKey {
            source_column: "credential_id",
            target_table: "operator_credentials",
            target_column: "credential_id",
        },
    ],
    indexes: &[
        IndexSpec { name: "operator_refresh_families_by_expiry", columns: &["expires_at_ms"] },
        IndexSpec {
            name: "operator_refresh_families_by_operator",
            columns: &["operator_id", "expires_at_ms"],
        },
    ],
};
const OPERATOR_REFRESH_TOKENS: TableSpec = TableSpec {
    name: "operator_refresh_tokens",
    columns: DEVICE_REFRESH_TOKENS.columns,
    foreign_keys: &[ForeignKey {
        source_column: "family_id",
        target_table: "operator_refresh_families",
        target_column: "family_id",
    }],
    indexes: &[IndexSpec { name: "operator_refresh_tokens_by_family", columns: &["family_id"] }],
};

const PAIRING_SESSIONS: TableSpec = TableSpec {
    name: "pairing_sessions",
    columns: &[
        ColumnSpec {
            name: "pairing_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "trusted_origin",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "responder_device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "capability_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "initiator_device_id",
            kind: LogicalType::Bytes,
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
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "state", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "slot_count",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "payload_bytes",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "approval_fingerprint",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "completed_revision",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[
        IndexSpec { name: "pairing_sessions_by_retention", columns: &["retain_until_ms"] },
        IndexSpec { name: "pairing_sessions_by_expiry", columns: &["state", "expires_at_ms"] },
    ],
};

const PAIRING_SLOTS: TableSpec = TableSpec {
    name: "pairing_slots",
    columns: &[
        ColumnSpec {
            name: "pairing_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "slot_index",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "payload",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "payload_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "pairing_id",
        target_table: "pairing_sessions",
        target_column: "pairing_id",
    }],
    indexes: &[],
};

const PAIRING_ADMISSION: TableSpec = TableSpec {
    name: "pairing_admission",
    columns: &[
        ColumnSpec {
            name: "endpoint",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "kind", kind: LogicalType::Integer, nullable: false, primary_key: true },
        ColumnSpec {
            name: "bucket_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "window_start_ms",
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
            name: "failure_streak",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_failure_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "cooldown_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "retain_until_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec { name: "pairing_admission_by_retention", columns: &["retain_until_ms"] }],
};

const SYNC_WRITE_ADMISSION: TableSpec = TableSpec {
    name: "sync_write_admission",
    columns: &[
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "requests_per_second",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec { name: "burst", kind: LogicalType::Bytes, nullable: false, primary_key: false },
        ColumnSpec {
            name: "tokens",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "refill_origin_ns",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "retire_at_ns",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "sync_write_admission_by_retirement",
        columns: &["retire_at_ns", "device_id"],
    }],
};

const SYNC_WRITE_ADMISSION_CLOCK: TableSpec = TableSpec {
    name: "sync_write_admission_clock",
    columns: &[
        ColumnSpec {
            name: "singleton",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "retired_through_ns",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_PASSWORD_PROBE_KEY: TableSpec = TableSpec {
    name: "account_password_probe_key",
    columns: &[
        ColumnSpec {
            name: "singleton",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "encrypted_key",
            kind: LogicalType::Bytes,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "created_at_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_PASSWORD_BOOTSTRAP: TableSpec = TableSpec {
    name: "account_password_bootstrap",
    columns: &[
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "origin", kind: LogicalType::Text, nullable: false, primary_key: false },
        ColumnSpec {
            name: "username",
            kind: LogicalType::Text,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "credential_generation",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "password_profile",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "password_salt",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "verifier",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "password_ark",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "personal_vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_signing_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_kem_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "account_id",
        target_table: "identity_accounts",
        target_column: "account_id",
    }],
    indexes: &[],
};

const ACCOUNT_OPERATION_RECEIPTS: TableSpec = TableSpec {
    name: "account_operation_receipts",
    columns: &[
        ColumnSpec {
            name: "operation_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "account_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "personal_vault_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "request_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "kind",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "device_signing_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "device_kem_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "account_signing_public_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "admitted_key_revision",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "committed_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[ForeignKey {
        source_column: "account_id",
        target_table: "identity_accounts",
        target_column: "account_id",
    }],
    indexes: &[
        IndexSpec { name: "account_operation_receipts_account", columns: &["account_id"] },
        IndexSpec {
            name: "account_operation_receipts_signing",
            columns: &["device_signing_public_key"],
        },
        IndexSpec { name: "account_operation_receipts_kem", columns: &["device_kem_public_key"] },
    ],
};

const ACCOUNT_USED_IDS: TableSpec = TableSpec {
    name: "account_used_ids",
    columns: &[ColumnSpec {
        name: "digest",
        kind: LogicalType::Bytes,
        nullable: false,
        primary_key: true,
    }],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_ID_RETENTION_GUARD: TableSpec = TableSpec {
    name: "account_id_retention_guard",
    columns: &[
        ColumnSpec {
            name: "singleton",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "row_ceiling",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "maintenance",
            kind: LogicalType::Boolean,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_ENTRY_STATE: TableSpec = TableSpec {
    name: "account_entry_state",
    columns: &[
        ColumnSpec {
            name: "singleton",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "time_high_water_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "rate_rows",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "challenge_rows",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_cleanup_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[],
};

const ACCOUNT_ENTRY_ADMISSION: TableSpec = TableSpec {
    name: "account_entry_admission",
    columns: &[
        ColumnSpec {
            name: "endpoint",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec { name: "kind", kind: LogicalType::Integer, nullable: false, primary_key: true },
        ColumnSpec {
            name: "bucket_key",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "window_start_ms",
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
            name: "failure_streak",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_failure_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "cooldown_until_ms",
            kind: LogicalType::Integer,
            nullable: true,
            primary_key: false,
        },
        ColumnSpec {
            name: "last_admitted_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "retire_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec { name: "account_entry_admission_retire", columns: &["retire_at_ms"] }],
};

const ACCOUNT_REQUEST_CHALLENGES: TableSpec = TableSpec {
    name: "account_request_challenges",
    columns: &[
        ColumnSpec {
            name: "attempt_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: true,
        },
        ColumnSpec {
            name: "nonce_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "origin_digest",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "kind",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "intent",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "operation_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "device_id",
            kind: LogicalType::Bytes,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "issued_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
        ColumnSpec {
            name: "expires_at_ms",
            kind: LogicalType::Integer,
            nullable: false,
            primary_key: false,
        },
    ],
    foreign_keys: &[],
    indexes: &[IndexSpec {
        name: "account_request_challenges_expiry",
        columns: &["expires_at_ms"],
    }],
};

const TABLES: &[TableSpec] = &[
    ACCOUNT_OPERATION_RECEIPTS,
    ACCOUNT_PASSWORD_BOOTSTRAP,
    ACCOUNT_ENTRY_STATE,
    ACCOUNT_ENTRY_ADMISSION,
    ACCOUNT_REQUEST_CHALLENGES,
    ACCOUNT_USED_IDS,
    ACCOUNT_ID_RETENTION_GUARD,
    ACCOUNT_PASSWORD_PROBE_KEY,
    SYNC_WRITE_ADMISSION,
    SYNC_WRITE_ADMISSION_CLOCK,
    PAIRING_SESSIONS,
    PAIRING_SLOTS,
    PAIRING_ADMISSION,
    OPERATOR_REFRESH_FAMILIES,
    OPERATOR_REFRESH_TOKENS,
    OPERATOR_AUTH_ADMISSION,
    OPERATOR_DPOP_REPLAYS,
    DEPLOYMENT_OPERATORS,
    OPERATOR_CREDENTIALS,
    OPERATOR_SETUP,
    OPERATOR_CEREMONIES,
    ORGANIZATIONS,
    AUDIT_EVENTS,
    AUDIT_CHECKPOINTS,
    DEPLOYMENT_AUDIT_EVENTS,
    DEPLOYMENT_AUDIT_CHECKPOINTS,
    DEVICE_ACCESS_TOKEN_KEYS,
    OPERATOR_ACCESS_TOKEN_KEYS,
    DEVICE_AUTH_CHALLENGES,
    DEVICE_REFRESH_FAMILIES,
    DEVICE_REFRESH_TOKENS,
    DEVICE_DPOP_REPLAYS,
    DEVICE_AUTH_ADMISSION,
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
    IDENTITY_ACCOUNTS,
    IDENTITY_DEVICES,
    PERSONAL_INVITATIONS,
    PERSONAL_ADMISSION,
    PERSONAL_INVITATION_ADMISSION,
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
        ("identity_devices", "active", "INTEGER")
        | ("identity_accounts", "password_owned", "INTEGER")
        | ("sync_objects" | "sync_object_versions", "tombstone", "INTEGER")
        | ("sync_vaults", "rotation_pending", "INTEGER")
        | ("account_id_retention_guard", "maintenance", "INTEGER") => Ok(LogicalType::Boolean),
        (_, _, "BLOB") => Ok(LogicalType::Bytes),
        (_, _, "TEXT") => Ok(LogicalType::Text),
        (_, _, "INTEGER") => Ok(LogicalType::Integer),
        _ => Err(format!("unsupported SQLite type {declared} for {table}.{column}")),
    }
}

#[cfg(feature = "postgres-integration")]
fn postgres_kind(table: &str, column: &str, declared: &str) -> Result<LogicalType, String> {
    match (table, column, declared) {
        ("identity_devices", "active", "boolean")
        | ("identity_accounts", "password_owned", "boolean")
        | ("sync_objects" | "sync_object_versions", "tombstone", "boolean")
        | ("sync_vaults", "rotation_pending", "boolean")
        | ("account_id_retention_guard", "maintenance", "boolean") => Ok(LogicalType::Boolean),
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
        "SELECT source_attribute.attname AS source_column,
                target_relation.relname AS target_table,
                target_attribute.attname AS target_column
         FROM pg_constraint fk
         JOIN pg_class source_relation ON source_relation.oid = fk.conrelid
         JOIN pg_namespace source_schema ON source_schema.oid = source_relation.relnamespace
         JOIN pg_class target_relation ON target_relation.oid = fk.confrelid
         CROSS JOIN LATERAL unnest(fk.conkey, fk.confkey)
             AS key_pair(source_attnum, target_attnum)
         JOIN pg_attribute source_attribute
             ON source_attribute.attrelid = source_relation.oid
            AND source_attribute.attnum = key_pair.source_attnum
         JOIN pg_attribute target_attribute
             ON target_attribute.attrelid = target_relation.oid
            AND target_attribute.attnum = key_pair.target_attnum
         WHERE fk.contype = 'f' AND source_schema.nspname = 'public'
           AND source_relation.relname = $1",
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
        "SELECT index_rel.relname AS name, attribute.attname AS column_name, index_data.indisunique AS unique_index FROM pg_class table_rel JOIN pg_namespace namespace_rel ON namespace_rel.oid = table_rel.relnamespace JOIN pg_index index_data ON index_data.indrelid = table_rel.oid JOIN pg_class index_rel ON index_rel.oid = index_data.indexrelid JOIN LATERAL unnest(index_data.indkey) WITH ORDINALITY AS key_data(attnum, position) ON TRUE JOIN pg_attribute attribute ON attribute.attrelid = table_rel.oid AND attribute.attnum = key_data.attnum WHERE namespace_rel.nspname = 'public' AND table_rel.relname = $1 AND NOT index_data.indisprimary ORDER BY index_rel.relname, key_data.position",
    )
    .bind(table)
    .fetch_all(pool)
    .await
    .map_err(|error| error.to_string())?;
    let mut indexes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let declared = TABLES.iter().find(|spec| spec.name == table).ok_or("unknown table")?;
    for row in rows {
        let name: String = row.try_get("name").map_err(|error| error.to_string())?;
        let unique: bool = row.try_get("unique_index").map_err(|error| error.to_string())?;
        if unique && !declared.indexes.iter().any(|index| index.name == name) {
            continue;
        }
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
            let normalized = source.to_ascii_lowercase();
            if !normalized.contains(&format!("create index {}", index.name))
                && !normalized.contains(&format!("create unique index {}", index.name))
            {
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
    const SQLITE_DEPLOYMENT_AUDIT: &str =
        include_str!("../migrations/sqlite/20261020000000_deployment_audit.sql");
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
    const SQLITE_PERSONAL_ENROLLMENT: &str =
        include_str!("../migrations/sqlite/20261020010000_personal_enrollment.sql");
    const SQLITE_PERSONAL_ADMISSION: &str =
        include_str!("../migrations/sqlite/20261020020000_personal_admission.sql");
    const SQLITE_DEVICE_TOKEN_KEYS: &str =
        include_str!("../migrations/sqlite/20261020030000_device_token_keys.sql");
    const SQLITE_OPERATOR_TOKEN_KEYS: &str =
        include_str!("../migrations/sqlite/20261022060000_operator_token_keys.sql");
    const SQLITE_OPERATOR_SETUP: &str =
        include_str!("../migrations/sqlite/20261022000000_operator_setup.sql");
    const SQLITE_OPERATOR_ADMISSION: &str =
        include_str!("../migrations/sqlite/20261022070000_operator_admission.sql");
    const SQLITE_OPERATOR_SESSIONS: &str =
        include_str!("../migrations/sqlite/20261022080000_operator_sessions.sql");
    const POSTGRES_OPERATOR_SESSIONS: &str =
        include_str!("../migrations/postgres/20261022080000_operator_sessions.sql");
    const POSTGRES_OPERATOR_ADMISSION: &str =
        include_str!("../migrations/postgres/20261022070000_operator_admission.sql");
    const POSTGRES_OPERATOR_SETUP: &str =
        include_str!("../migrations/postgres/20261022000000_operator_setup.sql");
    const SQLITE_DEVICE_AUTHENTICATION: &str =
        include_str!("../migrations/sqlite/20261020040000_device_authentication.sql");
    const POSTGRES_ORGANIZATIONS: &str =
        include_str!("../migrations/postgres/20261007000000_organizations.sql");
    const POSTGRES_AUDIT: &str =
        include_str!("../migrations/postgres/20261008030000_audit_chain.sql");
    const POSTGRES_DEPLOYMENT_AUDIT: &str =
        include_str!("../migrations/postgres/20261020000000_deployment_audit.sql");
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
    const POSTGRES_PERSONAL_ENROLLMENT: &str =
        include_str!("../migrations/postgres/20261020010000_personal_enrollment.sql");
    const POSTGRES_PERSONAL_ADMISSION: &str =
        include_str!("../migrations/postgres/20261020020000_personal_admission.sql");
    const POSTGRES_DEVICE_TOKEN_KEYS: &str =
        include_str!("../migrations/postgres/20261020030000_device_token_keys.sql");
    const POSTGRES_OPERATOR_TOKEN_KEYS: &str =
        include_str!("../migrations/postgres/20261022060000_operator_token_keys.sql");
    const POSTGRES_DEVICE_AUTHENTICATION: &str =
        include_str!("../migrations/postgres/20261020040000_device_authentication.sql");
    const SQLITE_PERSONAL_INVITATION_ADMISSION: &str =
        include_str!("../migrations/sqlite/20261023010000_personal_invitation_admission.sql");
    const POSTGRES_PERSONAL_INVITATION_ADMISSION: &str =
        include_str!("../migrations/postgres/20261023010000_personal_invitation_admission.sql");
    const SQLITE_PAIRING_ADMISSION: &str =
        include_str!("../migrations/sqlite/20261024020000_pairing_admission.sql");
    const POSTGRES_PAIRING_ADMISSION: &str =
        include_str!("../migrations/postgres/20261024020000_pairing_admission.sql");
    const SQLITE_PAIRING_SESSIONS: &str =
        include_str!("../migrations/sqlite/20261024030000_pairing_sessions.sql");
    const POSTGRES_PAIRING_SESSIONS: &str =
        include_str!("../migrations/postgres/20261024030000_pairing_sessions.sql");

    const SQLITE_SYNC_WRITE_ADMISSION: &str =
        include_str!("../migrations/sqlite/20261025000000_sync_write_admission.sql");
    const POSTGRES_SYNC_WRITE_ADMISSION: &str =
        include_str!("../migrations/postgres/20261025000000_sync_write_admission.sql");
    const SQLITE_ACCOUNT_PASSWORD_PROBE_KEY: &str =
        include_str!("../migrations/sqlite/20261025020000_account_password_probe_key.sql");
    const POSTGRES_ACCOUNT_PASSWORD_PROBE_KEY: &str =
        include_str!("../migrations/postgres/20261025020000_account_password_probe_key.sql");
    const SQLITE_ACCEPTED_ACCOUNT_KEY_PUT: &str =
        include_str!("../migrations/sqlite/20261025030000_accepted_account_key_put.sql");
    const POSTGRES_ACCEPTED_ACCOUNT_KEY_PUT: &str =
        include_str!("../migrations/postgres/20261025030000_accepted_account_key_put.sql");
    const SQLITE_ACCOUNT_USED_IDS: &str =
        include_str!("../migrations/sqlite/20261025040000_account_used_ids.sql");
    const POSTGRES_ACCOUNT_USED_IDS: &str =
        include_str!("../migrations/postgres/20261025040000_account_used_ids.sql");
    const SQLITE_ACCOUNT_PASSWORD_BOOTSTRAP: &str =
        include_str!("../migrations/sqlite/20261025050000_account_password_bootstrap.sql");
    const POSTGRES_ACCOUNT_PASSWORD_BOOTSTRAP: &str =
        include_str!("../migrations/postgres/20261025050000_account_password_bootstrap.sql");
    const SQLITE_ACCOUNT_ENTRY_STATE: &str =
        include_str!("../migrations/sqlite/20261025060000_account_entry_state.sql");
    const POSTGRES_ACCOUNT_ENTRY_STATE: &str =
        include_str!("../migrations/postgres/20261025060000_account_entry_state.sql");
    const SQLITE_ACCOUNT_OPERATION_RECEIPTS: &str =
        include_str!("../migrations/sqlite/20261025070000_account_operation_receipts.sql");
    const POSTGRES_ACCOUNT_OPERATION_RECEIPTS: &str =
        include_str!("../migrations/postgres/20261025070000_account_operation_receipts.sql");

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
            SQLITE_DEPLOYMENT_AUDIT,
            SQLITE_SYNC,
            SQLITE_KEYS,
            SQLITE_JOBS,
            SQLITE_MEMBER_REMOVAL,
            SQLITE_PERSONAL_VAULTS,
            SQLITE_EPOCH_RETIREMENT,
            SQLITE_PERSONAL_ENROLLMENT,
            SQLITE_PERSONAL_ADMISSION,
            SQLITE_DEVICE_TOKEN_KEYS,
            SQLITE_DEVICE_AUTHENTICATION,
            SQLITE_OPERATOR_SETUP,
            SQLITE_OPERATOR_TOKEN_KEYS,
            SQLITE_OPERATOR_ADMISSION,
            SQLITE_OPERATOR_SESSIONS,
            SQLITE_PERSONAL_INVITATION_ADMISSION,
            SQLITE_PAIRING_ADMISSION,
            SQLITE_PAIRING_SESSIONS,
            SQLITE_SYNC_WRITE_ADMISSION,
            SQLITE_ACCOUNT_PASSWORD_PROBE_KEY,
            SQLITE_ACCEPTED_ACCOUNT_KEY_PUT,
            SQLITE_ACCOUNT_USED_IDS,
            SQLITE_ACCOUNT_PASSWORD_BOOTSTRAP,
            SQLITE_ACCOUNT_ENTRY_STATE,
            SQLITE_ACCOUNT_OPERATION_RECEIPTS,
        ];
        let postgres = [
            POSTGRES_ORGANIZATIONS,
            POSTGRES_AUDIT,
            POSTGRES_DEPLOYMENT_AUDIT,
            POSTGRES_SYNC,
            POSTGRES_KEYS,
            POSTGRES_JOBS,
            POSTGRES_MEMBER_REMOVAL,
            POSTGRES_PERSONAL_VAULTS,
            POSTGRES_EPOCH_RETIREMENT,
            POSTGRES_PERSONAL_ENROLLMENT,
            POSTGRES_PERSONAL_ADMISSION,
            POSTGRES_DEVICE_TOKEN_KEYS,
            POSTGRES_DEVICE_AUTHENTICATION,
            POSTGRES_OPERATOR_SETUP,
            POSTGRES_OPERATOR_TOKEN_KEYS,
            POSTGRES_OPERATOR_ADMISSION,
            POSTGRES_OPERATOR_SESSIONS,
            POSTGRES_PERSONAL_INVITATION_ADMISSION,
            POSTGRES_PAIRING_ADMISSION,
            POSTGRES_PAIRING_SESSIONS,
            POSTGRES_SYNC_WRITE_ADMISSION,
            POSTGRES_ACCOUNT_PASSWORD_PROBE_KEY,
            POSTGRES_ACCEPTED_ACCOUNT_KEY_PUT,
            POSTGRES_ACCOUNT_USED_IDS,
            POSTGRES_ACCOUNT_PASSWORD_BOOTSTRAP,
            POSTGRES_ACCOUNT_ENTRY_STATE,
            POSTGRES_ACCOUNT_OPERATION_RECEIPTS,
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
    #[allow(clippy::too_many_lines)]
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
        assert_eq!(
            migration_count,
            i64::try_from(crate::POSTGRES_MIGRATIONS.iter().count()).unwrap()
        );
        postgres.pool().close().await;
        let reopened = crate::PostgresStore::connect(database_url)
            .await
            .expect("PostgreSQL migration replay is idempotent");
        let replay_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(reopened.pool())
            .await
            .expect("read replayed migration history");
        assert_eq!(replay_count, migration_count);

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
        let account = uuid::Uuid::new_v4().into_bytes();
        let key_update = crate::account_keys::AccountKeyBundleUpdate {
            revision: 1,
            device_wraps: vec![crate::account_keys::DeviceWrap {
                device_id: [7; 16],
                wrapped_ark: vec![7, 1],
            }],
            account_signing_key: vec![7, 2],
            account_kem_key: vec![7, 3],
            recovery_blob: vec![7, 4],
            signature: [7; 64],
        };
        assert_eq!(
            reopened
                .put_account_key_bundle(account, &key_update)
                .await
                .expect("put PostgreSQL account key"),
            crate::account_keys::AccountKeyBundlePut::Applied { revision: 1 }
        );
        reopened
            .replace_account_key_statements(account, &[vec![2], vec![1]], &[vec![3]])
            .await
            .expect("replace PostgreSQL account key statements");
        let key_bundle = reopened
            .get_account_key_bundle(account, [7; 16])
            .await
            .expect("get PostgreSQL account key");
        assert_eq!(key_bundle.wrapped_ark, vec![7, 1]);
        assert_eq!(key_bundle.certificates, vec![vec![1], vec![2]]);
        let job_id = uuid::Uuid::new_v4().into_bytes();
        reopened
            .enqueue_job(job_id, "postgres-parity", b"payload", 0)
            .await
            .expect("enqueue PostgreSQL job");
        let created_at_ms: i64 = sqlx::query_scalar("SELECT created_at_ms FROM jobs WHERE id = $1")
            .bind(job_id.as_slice())
            .fetch_one(reopened.pool())
            .await
            .expect("read PostgreSQL job creation time");
        let claimed = reopened
            .claim_job("postgres-worker", created_at_ms, 1_000)
            .await
            .expect("claim PostgreSQL job")
            .expect("PostgreSQL job is available");
        assert_eq!(claimed.id, job_id);
        reopened
            .complete_job(job_id, "postgres-worker", created_at_ms + 1)
            .await
            .expect("complete PostgreSQL job");
        sqlx::query("DELETE FROM sync_account_key_bundles WHERE account_id = $1")
            .bind(account.as_slice())
            .execute(reopened.pool())
            .await
            .expect("clean PostgreSQL account key");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(organization.as_slice())
            .execute(reopened.pool())
            .await
            .expect("clean PostgreSQL parity organization");
        reopened.pool().close().await;
    }
}
