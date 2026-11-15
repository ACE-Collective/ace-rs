//! The database role of the AI investigation API's process: what it is granted, and what the role a
//! process connected as can really do.
//!
//! `ace serve-ai` connects as a member of [`ROLE`], which migration 0064 makes and grants. When the
//! process starts it reads what its login can do, here, and refuses to serve if that is more than
//! [`GRANTED`]: ace3's AI container asserts it holds no encryption capability and no key but its
//! backends', and this is the same assertion about the database.
//!
//! **What the role can do.** Read alerts, their observables, tags, detections, results and files' rows
//! (`analysis`), events and what they hold (`events`), and the search index (`search`); check an API
//! key by the hash of its token and read its grants, its owner's name and whether the owner is
//! enabled (`service`); insert an audit row; and keep the rate limiter's two tables (`ai`).
//!
//! **What it can't.** It can't read a GUI session, a password hash, the email archive, the bucket's
//! index of objects, a list, a hunt's state, the queue, SVS, the YARA rulesets, or its own audit
//! rows. It can't change anything but the limiter's tables and a new audit row: not an alert, a
//! disposition, a grant, a key, a user. It can't create or drop anything.

use std::collections::BTreeSet;

use ace_core::db::{Db, DbError};

/// The role migration 0064 grants. It can't log in; a deployment's login role is a member of it.
pub const ROLE: &str = "ace4_ai";

/// The schemas the role may use.
pub const SCHEMAS: &[&str] = &["ai", "analysis", "events", "search", "service", "svs"];

const READ: &[&str] = &["SELECT"];
const KEEP: &[&str] = &["DELETE", "INSERT", "SELECT", "UPDATE"];

/// What the role holds on whole tables: migration 0064's grants, which `ace-service`'s tests hold
/// this list to.
pub const GRANTED: &[(&str, &[&str])] = &[
    // the rate limiter's state
    ("ai.inflight", KEEP),
    ("ai.windows", KEEP),
    // alerts
    ("analysis.detection_verdicts", READ),
    ("analysis.detections", READ),
    ("analysis.files", READ),
    ("analysis.observables", READ),
    ("analysis.relationships", READ),
    ("analysis.results", READ),
    ("analysis.roots", READ),
    // events
    ("events.campaigns", READ),
    ("events.event_alerts", READ),
    ("events.event_malware", READ),
    ("events.event_tags", READ),
    ("events.events", READ),
    ("events.malware", READ),
    ("events.malware_threats", READ),
    ("events.prevention_tools", READ),
    ("events.remediations", READ),
    ("events.risk_levels", READ),
    ("events.statuses", READ),
    ("events.threat_types", READ),
    ("events.types", READ),
    ("events.vectors", READ),
    // which migration the database is at
    ("public._sqlx_migrations", READ),
    // the search index
    ("search.chunks", READ),
    ("search.indexed", READ),
    // API keys and what they and their owners hold
    ("service.api_keys", READ),
    ("service.group_members", READ),
    ("service.permissions", READ),
    // an audit row: written, never read
    ("service.audit", &["INSERT"]),
    // whether an alert is an SVS test run's, and whether the run is reviewed
    ("svs.attributions", READ),
    ("svs.runs", READ),
];

/// What the role holds on columns of a table it holds nothing on as a whole: a user's name, whether
/// they are enabled and their queue, and not their password's hash.
pub const GRANTED_COLUMNS: &[(&str, &[&str], &str)] = &[(
    "service.users",
    &["display_name", "enabled", "id", "queue", "username"],
    "SELECT",
)];

/// What a login can do in the database it is connected to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolePrivileges {
    /// The login: `session_user`, whatever role the session has since set.
    pub user: String,
    /// What the role is beyond a plain login: `superuser`, `createrole`, `createdb`, `replication`,
    /// `bypassrls`, and `owner of the database` or `owner of <relation>`.
    pub powers: Vec<String>,
    /// The roles it is a member of, itself left out.
    pub member_of: BTreeSet<String>,
    /// The schemas it may use, and `<schema> (create)` for one it may create in; `database (create)`
    /// for the database.
    pub schemas: BTreeSet<String>,
    /// `(relation, privilege)` over every table, view and sequence outside Postgres' own schemas.
    pub tables: BTreeSet<(String, String)>,
    /// `(relation, column, privilege)` where the privilege isn't held on the whole table.
    pub columns: BTreeSet<(String, String, String)>,
}

impl RolePrivileges {
    /// Whether the role holds `privilege` on `relation`, wholly or on any column.
    pub fn holds(&self, relation: &str, privilege: &str) -> bool {
        self.tables
            .contains(&(relation.to_owned(), privilege.to_owned()))
            || self
                .columns
                .iter()
                .any(|(table, _, held)| table == relation && held == privilege)
    }

    /// The relations of `schema` the role can read any of.
    pub fn reads_in(&self, schema: &str) -> Vec<String> {
        let prefix = format!("{schema}.");
        let mut found: BTreeSet<&str> = BTreeSet::new();
        for (relation, privilege) in &self.tables {
            if relation.starts_with(&prefix) && privilege == "SELECT" {
                found.insert(relation);
            }
        }
        for (relation, _, privilege) in &self.columns {
            if relation.starts_with(&prefix) && privilege == "SELECT" {
                found.insert(relation);
            }
        }
        found.into_iter().map(str::to_owned).collect()
    }

    /// Everything the role can do that [`GRANTED`] doesn't give it, in words: empty for a role that
    /// is a member of [`ROLE`] and nothing more.
    pub fn beyond(&self) -> Vec<String> {
        let mut found: Vec<String> = self.powers.clone();
        for role in &self.member_of {
            if role != ROLE {
                found.push(format!("member of the role {role}"));
            }
        }
        for schema in &self.schemas {
            // every role may use `public`, which holds only the migrations' table here
            if schema != "public" && !SCHEMAS.contains(&schema.as_str()) {
                found.push(format!("schema {schema}"));
            }
        }
        for (relation, privilege) in &self.tables {
            let granted = GRANTED.iter().any(|(table, privileges)| {
                table == relation && privileges.contains(&privilege.as_str())
            });
            if !granted {
                found.push(format!("{privilege} on {relation}"));
            }
        }
        for (relation, column, privilege) in &self.columns {
            let granted = GRANTED_COLUMNS.iter().any(|(table, columns, held)| {
                table == relation && held == privilege && columns.contains(&column.as_str())
            });
            if !granted {
                found.push(format!("{privilege} on {relation}.{column}"));
            }
        }
        found
    }

    /// What [`GRANTED`] gives that the role lacks: a role too small to serve the API.
    pub fn missing(&self) -> Vec<String> {
        let mut found = Vec::new();
        for (relation, privileges) in GRANTED {
            for privilege in *privileges {
                if !self
                    .tables
                    .contains(&((*relation).to_owned(), (*privilege).to_owned()))
                {
                    found.push(format!("{privilege} on {relation}"));
                }
            }
        }
        for (relation, columns, privilege) in GRANTED_COLUMNS {
            for column in *columns {
                // on the column, or on the whole table
                let held = self.columns.contains(&(
                    (*relation).to_owned(),
                    (*column).to_owned(),
                    (*privilege).to_owned(),
                )) || self
                    .tables
                    .contains(&((*relation).to_owned(), (*privilege).to_owned()));
                if !held {
                    found.push(format!("{privilege} on {relation}.{column}"));
                }
            }
        }
        found
    }
}

/// Outside Postgres' own schemas: a condition on `pg_namespace n`.
macro_rules! ours {
    () => {
        "n.nspname NOT IN ('pg_catalog', 'information_schema') \
         AND n.nspname NOT LIKE 'pg\\_toast%' AND n.nspname NOT LIKE 'pg\\_temp%'"
    };
}

/// What the login `db` is connected as can do. It asks about `session_user`, so a session that set
/// another role is still judged by its login, and by every role the login is a member of.
pub async fn role_privileges(db: &Db) -> Result<RolePrivileges, DbError> {
    let login: String = sqlx::query_scalar("SELECT session_user::text")
        .fetch_one(db.pool())
        .await?;
    role_privileges_of(db, &login).await
}

/// What the role named `role` can do in the database `db` is connected to, itself and through every
/// role it is a member of.
pub async fn role_privileges_of(db: &Db, role: &str) -> Result<RolePrivileges, DbError> {
    let pool = db.pool();
    let (user, superuser, createrole, createdb, replication, bypassrls, owns_database): (
        String,
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT r.rolname::text, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
                r.rolbypassrls,
                (SELECT d.datdba = r.oid FROM pg_catalog.pg_database d
                 WHERE d.datname = current_database())
         FROM pg_catalog.pg_roles r WHERE r.rolname = $1",
    )
    .bind(role)
    .fetch_one(pool)
    .await?;
    let mut powers: Vec<String> = [
        (superuser, "superuser"),
        (createrole, "createrole"),
        (createdb, "createdb"),
        (replication, "replication"),
        (bypassrls, "bypassrls"),
        (owns_database, "owner of the database"),
    ]
    .into_iter()
    .filter(|(held, _)| *held)
    .map(|(_, name)| name.to_owned())
    .collect();
    let owned: Vec<String> = sqlx::query_scalar(concat!(
        "SELECT n.nspname || '.' || c.relname
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE ",
        ours!(),
        " AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
           AND pg_catalog.pg_get_userbyid(c.relowner) = $1
         ORDER BY 1 LIMIT 20"
    ))
    .bind(role)
    .fetch_all(pool)
    .await?;
    powers.extend(
        owned
            .into_iter()
            .map(|relation| format!("owner of {relation}")),
    );

    let member_of: Vec<String> = sqlx::query_scalar(
        "SELECT r.rolname::text FROM pg_catalog.pg_roles r
         WHERE r.rolname <> $1 AND pg_catalog.pg_has_role($1::name, r.oid, 'MEMBER')",
    )
    .bind(role)
    .fetch_all(pool)
    .await?;

    let mut schemas: BTreeSet<String> = sqlx::query_scalar(concat!(
        "SELECT CASE WHEN p.privilege = 'CREATE' THEN n.nspname || ' (create)' ELSE n.nspname::text END
         FROM pg_catalog.pg_namespace n
         CROSS JOIN unnest(ARRAY['USAGE', 'CREATE']) AS p(privilege)
         WHERE ",
        ours!(),
        " AND pg_catalog.has_schema_privilege($1::name, n.oid, p.privilege)"
    ))
    .bind(role)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();
    let creates: bool = sqlx::query_scalar(
        "SELECT pg_catalog.has_database_privilege($1::name, current_database(), 'CREATE')",
    )
    .bind(role)
    .fetch_one(pool)
    .await?;
    if creates {
        schemas.insert("database (create)".to_owned());
    }

    let tables: Vec<(String, String)> = sqlx::query_as(concat!(
        "SELECT n.nspname || '.' || c.relname, p.privilege
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES',
                                 'TRIGGER']) AS p(privilege)
         WHERE ",
        ours!(),
        " AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND pg_catalog.has_table_privilege($1::name, c.oid, p.privilege)
         UNION ALL
         SELECT n.nspname || '.' || c.relname, p.privilege
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p(privilege)
         WHERE ",
        ours!(),
        " AND c.relkind = 'S'
           AND pg_catalog.has_sequence_privilege($1::name, c.oid, p.privilege)"
    ))
    .bind(role)
    .fetch_all(pool)
    .await?;
    let columns: Vec<(String, String, String)> = sqlx::query_as(concat!(
        "SELECT n.nspname || '.' || c.relname, a.attname::text, p.privilege
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
         CROSS JOIN unnest(ARRAY['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) AS p(privilege)
         WHERE ",
        ours!(),
        " AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
           AND NOT pg_catalog.has_table_privilege($1::name, c.oid, p.privilege)
           AND pg_catalog.has_column_privilege($1::name, c.oid, a.attnum, p.privilege)"
    ))
    .bind(role)
    .fetch_all(pool)
    .await?;

    Ok(RolePrivileges {
        user,
        powers,
        member_of: member_of.into_iter().collect(),
        schemas,
        tables: tables.into_iter().collect(),
        columns: columns.into_iter().collect(),
    })
}

/// The newest migration the database has applied, or None when the login can't read the migrations'
/// table or it holds none.
pub async fn schema_version(db: &Db) -> Result<Option<i64>, DbError> {
    Ok(
        sqlx::query_scalar("SELECT max(version) FROM public._sqlx_migrations WHERE success")
            .fetch_one(db.pool())
            .await?,
    )
}
