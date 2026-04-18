// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Post-deployment health monitoring and anomaly detection.
//!
//! **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
//! Monitors printer health after firmware deployment and triggers automatic
//! rollback if error rates exceed baseline + 2 sigma.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pf_common::fleet::PrinterId;

use crate::config::AnomalyConfig;

/// A single health sample collected from a printer after firmware deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSample {
    /// The printer that reported this sample.
    pub printer_id: PrinterId,

    /// The rollout this sample is associated with.
    pub rollout_id: Uuid,

    /// Timestamp of the sample.
    pub sampled_at: DateTime<Utc>,

    /// Whether the printer reported an error state.
    pub is_error: bool,

    /// Printer-reported error code (if any).
    pub error_code: Option<String>,

    /// Pages printed since firmware update.
    pub pages_since_update: u64,
}

/// Baseline health statistics for a printer model prior to firmware deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthBaseline {
    /// Mean error rate (errors per sample) before the firmware update.
    pub mean_error_rate: f64,

    /// Standard deviation of the error rate.
    pub std_deviation: f64,

    /// Number of samples in the baseline.
    pub sample_count: u32,
}

/// Anomaly detection verdict for a rollout phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyVerdict {
    /// No anomaly detected; error rate is within expected bounds.
    Normal,

    /// Error rate exceeds the configured sigma threshold.
    AnomalyDetected,

    /// Insufficient samples to make a determination.
    InsufficientData,
}

/// Result of an anomaly detection evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyEvaluation {
    /// The rollout being monitored.
    pub rollout_id: Uuid,

    /// The detection verdict.
    pub verdict: AnomalyVerdict,

    /// Observed error rate during the current soak period.
    pub observed_error_rate: f64,

    /// The threshold that was used (baseline mean + sigma * `std_dev`).
    pub threshold: f64,

    /// Number of samples evaluated.
    pub sample_count: u32,

    /// Timestamp of evaluation.
    pub evaluated_at: DateTime<Utc>,
}

/// Evaluate collected health samples against a baseline to detect anomalies.
///
/// **NIST 800-53 Rev 5:** SI-2 — Flaw Remediation
/// Auto-halts on anomaly (error rate > baseline + configured sigma * `std_dev`).
///
/// # Errors
///
/// This function does not return errors; it returns [`AnomalyVerdict::InsufficientData`]
/// if there are not enough samples.
#[must_use]
pub fn evaluate_anomaly(
    rollout_id: Uuid,
    samples: &[HealthSample],
    baseline: &HealthBaseline,
    config: &AnomalyConfig,
) -> AnomalyEvaluation {
    let sample_count = u32::try_from(samples.len()).unwrap_or(u32::MAX);

    if sample_count < config.min_samples {
        return AnomalyEvaluation {
            rollout_id,
            verdict: AnomalyVerdict::InsufficientData,
            observed_error_rate: 0.0,
            threshold: 0.0,
            sample_count,
            evaluated_at: Utc::now(),
        };
    }

    let error_count = samples.iter().filter(|s| s.is_error).count();
    #[allow(clippy::cast_precision_loss)]
    let observed_error_rate = error_count as f64 / samples.len() as f64;
    let threshold = baseline.mean_error_rate + (config.sigma_threshold * baseline.std_deviation);

    let verdict = if observed_error_rate > threshold {
        tracing::warn!(
            rollout_id = %rollout_id,
            observed = %observed_error_rate,
            threshold = %threshold,
            "anomaly detected: error rate exceeds threshold"
        );
        AnomalyVerdict::AnomalyDetected
    } else {
        AnomalyVerdict::Normal
    };

    AnomalyEvaluation {
        rollout_id,
        verdict,
        observed_error_rate,
        threshold,
        sample_count,
        evaluated_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_samples(total: usize, errors: usize, rollout_id: Uuid) -> Vec<HealthSample> {
        let printer_id = PrinterId::new("PRN-0042").unwrap();
        (0..total)
            .map(|i| HealthSample {
                printer_id: printer_id.clone(),
                rollout_id,
                sampled_at: Utc::now(),
                is_error: i < errors,
                error_code: if i < errors {
                    Some("E001".to_string())
                } else {
                    None
                },
                pages_since_update: u64::try_from(i * 10).unwrap_or(0),
            })
            .collect()
    }

    #[test]
    fn nist_si2_anomaly_detected_when_error_rate_exceeds_threshold() {
        // NIST 800-53 Rev 5: SI-2 — Anomaly triggers rollback
        let rollout_id = Uuid::new_v4();
        // 8 errors out of 10 samples = 0.8 error rate
        let samples = make_samples(10, 8, rollout_id);
        let baseline = HealthBaseline {
            mean_error_rate: 0.05,
            std_deviation: 0.02,
            sample_count: 100,
        };
        let config = AnomalyConfig {
            sigma_threshold: 2.0,
            min_samples: 5,
            poll_interval_secs: 60,
        };
        let eval = evaluate_anomaly(rollout_id, &samples, &baseline, &config);
        assert_eq!(eval.verdict, AnomalyVerdict::AnomalyDetected);
        assert!(eval.observed_error_rate > eval.threshold);
    }

    #[test]
    fn nist_si2_normal_when_error_rate_within_threshold() {
        // NIST 800-53 Rev 5: SI-2 — Normal operation passes
        let rollout_id = Uuid::new_v4();
        // 0 errors out of 10 samples
        let samples = make_samples(10, 0, rollout_id);
        let baseline = HealthBaseline {
            mean_error_rate: 0.05,
            std_deviation: 0.02,
            sample_count: 100,
        };
        let config = AnomalyConfig {
            sigma_threshold: 2.0,
            min_samples: 5,
            poll_interval_secs: 60,
        };
        let eval = evaluate_anomaly(rollout_id, &samples, &baseline, &config);
        assert_eq!(eval.verdict, AnomalyVerdict::Normal);
    }

    #[test]
    fn insufficient_data_when_below_min_samples() {
        let rollout_id = Uuid::new_v4();
        let samples = make_samples(3, 0, rollout_id);
        let baseline = HealthBaseline {
            mean_error_rate: 0.05,
            std_deviation: 0.02,
            sample_count: 100,
        };
        let config = AnomalyConfig {
            sigma_threshold: 2.0,
            min_samples: 10,
            poll_interval_secs: 60,
        };
        let eval = evaluate_anomaly(rollout_id, &samples, &baseline, &config);
        assert_eq!(eval.verdict, AnomalyVerdict::InsufficientData);
    }

    #[test]
    fn evaluation_records_correct_sample_count() {
        let rollout_id = Uuid::new_v4();
        let samples = make_samples(15, 1, rollout_id);
        let baseline = HealthBaseline {
            mean_error_rate: 0.1,
            std_deviation: 0.05,
            sample_count: 50,
        };
        let config = AnomalyConfig::default();
        let eval = evaluate_anomaly(rollout_id, &samples, &baseline, &config);
        assert_eq!(eval.sample_count, 15);
    }
}
