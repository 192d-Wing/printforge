// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Database pool factory, migration runner, and health check.
//!
//! Provides shared database infrastructure used by all `PrintForge` crates
//! that connect to `PostgreSQL`.

use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tracing::info;

use crate::config::DatabaseConfig;
use crate::error::CommonError;

/// Creates a `PostgreSQL` connection pool from the provided configuration.
///
/// The password is extracted via [`secrecy::ExposeSecret`] and never logged.
/// The pool is configured with `max_connections` from the [`DatabaseConfig`].
pub async fn create_pool(cfg: &DatabaseConfig) -> Result<PgPool, CommonError> {
    let password = cfg
        .password
        .as_ref()
        .map(|s| s.expose_secret().to_string())
        .unwrap_or_default();

    let connection_string = format!(
        "postgres://{}:{}@{}:{}/{}",
        cfg.username, password, cfg.host, cfg.port, cfg.database,
    );

    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .connect(&connection_string)
        .await
        .map_err(|e| CommonError::Database(e.to_string()))?;

    info!(
        host = %cfg.host,
        port = cfg.port,
        database = %cfg.database,
        max_connections = cfg.max_connections,
        "database connection pool created"
    );

    Ok(pool)
}

/// Runs embedded SQL migrations against the database.
///
/// Migrations are loaded at compile time from `../../migrations` (the workspace
/// root `migrations/` directory).
pub async fn run_migrations(pool: &PgPool) -> Result<(), CommonError> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|e| CommonError::Database(e.to_string()))?;

    info!("database migrations applied successfully");
    Ok(())
}

/// Verifies database connectivity by executing `SELECT 1`.
///
/// Intended for use in health-check / readiness endpoints.
pub async fn health_check(pool: &PgPool) -> Result<(), CommonError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .map_err(|e| CommonError::Database(e.to_string()))?;

    Ok(())
}

// Compilation of this module verifies that create_pool, run_migrations, and
// health_check exist with correct signatures. No runtime test is needed —
// we cannot connect to a real database in unit tests.
