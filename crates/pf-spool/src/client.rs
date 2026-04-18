// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! S3 client wrapper for `RustFS` object storage.
//!
//! Provides a thin wrapper around `aws-sdk-s3` configured for `RustFS`
//! (S3-compatible, path-style addressing). Credential resolution follows
//! the standard AWS SDK chain (environment variables, profiles, IMDS) with
//! an optional fallback to explicit credentials from [`SpoolConfig`].

use std::collections::HashMap;

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use secrecy::ExposeSecret;

use crate::config::SpoolConfig;
use crate::error::SpoolError;

/// Wrapper around the `aws-sdk-s3` client configured for `RustFS`.
#[derive(Debug, Clone)]
pub struct S3Client {
    client: Client,
    bucket: String,
}

impl S3Client {
    /// Create a new S3 client from the spool configuration.
    ///
    /// Builds the client with path-style addressing enabled (required for
    /// `RustFS`) and a custom endpoint URL. Credentials are resolved in
    /// order of precedence:
    ///
    /// 1. Explicit `access_key_id` / `secret_access_key` from [`SpoolConfig`]
    /// 2. Standard AWS SDK environment chain (`AWS_ACCESS_KEY_ID`,
    ///    `AWS_SECRET_ACCESS_KEY`, instance profile, etc.)
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Config` if no credentials can be resolved from
    /// either the config or the environment.
    pub async fn new(config: &SpoolConfig) -> Result<Self, SpoolError> {
        let client = if config.access_key_id.is_some() && config.secret_access_key.is_some() {
            // Explicit credentials from config take precedence.
            let access_key = config
                .access_key_id
                .as_ref()
                .ok_or_else(|| SpoolError::Config("S3 access_key_id is required".into()))?;
            let secret_key = config
                .secret_access_key
                .as_ref()
                .ok_or_else(|| SpoolError::Config("S3 secret_access_key is required".into()))?;

            let credentials = Credentials::new(
                access_key.expose_secret(),
                secret_key.expose_secret(),
                None,
                None,
                "printforge-spool",
            );

            let s3_config = aws_sdk_s3::Config::builder()
                .behavior_version(BehaviorVersion::latest())
                .endpoint_url(&config.endpoint)
                .region(Region::new(config.region.clone()))
                .credentials_provider(credentials)
                .force_path_style(config.force_path_style)
                .build();

            Client::from_conf(s3_config)
        } else {
            // Fall back to the standard AWS SDK credential chain (env vars,
            // instance profile, etc.) while still honouring the configured
            // endpoint URL and path-style setting.
            let sdk_config = aws_config::defaults(BehaviorVersion::latest())
                .endpoint_url(&config.endpoint)
                .region(Region::new(config.region.clone()))
                .load()
                .await;

            let s3_config = aws_sdk_s3::config::Builder::from(&sdk_config)
                .force_path_style(config.force_path_style)
                .build();

            Client::from_conf(s3_config)
        };

        tracing::info!(
            endpoint = %config.endpoint,
            bucket = %config.bucket,
            region = %config.region,
            path_style = config.force_path_style,
            "S3 client initialised for RustFS"
        );

        Ok(Self {
            client,
            bucket: config.bucket.clone(),
        })
    }

    /// Upload an object to the spool bucket.
    ///
    /// Attaches the given `content_type` and optional string metadata to the
    /// object. Metadata keys are lower-cased by the S3 API and prefixed with
    /// `x-amz-meta-` on the wire.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` if the S3 PUT operation fails.
    pub async fn put_object(
        &self,
        key: &str,
        data: Vec<u8>,
        content_type: &str,
        metadata: Option<&HashMap<String, String>>,
    ) -> Result<(), SpoolError> {
        let mut req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .body(ByteStream::from(data));

        if let Some(meta) = metadata {
            for (k, v) in meta {
                req = req.metadata(k, v);
            }
        }

        req.send()
            .await
            .map_err(|e| SpoolError::Storage(format!("S3 PUT failed for key {key}: {e}")))?;
        Ok(())
    }

    /// Download an object from the spool bucket.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::NotFound` if the object does not exist.
    /// Returns `SpoolError::Storage` for other S3 errors.
    pub async fn get_object(&self, key: &str) -> Result<Vec<u8>, SpoolError> {
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| {
                let msg = format!("{e}");
                if msg.contains("NoSuchKey") || msg.contains("404") {
                    SpoolError::NotFound(key.to_string())
                } else {
                    SpoolError::Storage(format!("S3 GET failed for key {key}: {e}"))
                }
            })?;

        let bytes =
            resp.body.collect().await.map_err(|e| {
                SpoolError::Storage(format!("S3 body read failed for key {key}: {e}"))
            })?;

        Ok(bytes.to_vec())
    }

    /// Delete an object from the spool bucket.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` if the S3 DELETE operation fails.
    pub async fn delete_object(&self, key: &str) -> Result<(), SpoolError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| SpoolError::Storage(format!("S3 DELETE failed for key {key}: {e}")))?;
        Ok(())
    }

    /// Check if an object exists in the spool bucket via a HEAD request.
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` on S3 communication failure.
    pub async fn object_exists(&self, key: &str) -> Result<bool, SpoolError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("NotFound") || msg.contains("404") {
                    Ok(false)
                } else {
                    Err(SpoolError::Storage(format!(
                        "S3 HEAD failed for key {key}: {e}"
                    )))
                }
            }
        }
    }

    /// Create the spool bucket if it does not already exist.
    ///
    /// Intended for local development and test environments where `RustFS`
    /// starts without pre-created buckets. Production environments should
    /// provision buckets via infrastructure-as-code (Helm/Terraform).
    ///
    /// # Errors
    ///
    /// Returns `SpoolError::Storage` if the `CreateBucket` call fails for
    /// reasons other than the bucket already existing.
    pub async fn ensure_bucket(&self) -> Result<(), SpoolError> {
        match self
            .client
            .create_bucket()
            .bucket(&self.bucket)
            .send()
            .await
        {
            Ok(_) => {
                tracing::info!(bucket = %self.bucket, "created spool bucket");
                Ok(())
            }
            Err(e) => {
                let msg = format!("{e}");
                // S3 returns BucketAlreadyOwnedByYou (or BucketAlreadyExists
                // on some implementations) when the bucket is already present.
                if msg.contains("BucketAlreadyOwnedByYou")
                    || msg.contains("BucketAlreadyExists")
                    || msg.contains("409")
                {
                    tracing::debug!(bucket = %self.bucket, "spool bucket already exists");
                    Ok(())
                } else {
                    Err(SpoolError::Storage(format!(
                        "failed to create bucket {}: {e}",
                        self.bucket
                    )))
                }
            }
        }
    }

    /// Return a reference to the bucket name.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}
