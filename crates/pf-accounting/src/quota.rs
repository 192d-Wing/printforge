// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PrintForge Contributors

//! Quota tracking: monthly page counts, color page counts, burst tracking,
//! and reset scheduling.
//!
//! **Note:** Quota is *tracked* here but *enforced* in `pf-policy-engine`.
//! This crate maintains the counters; the policy engine queries them
//! during job evaluation.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use pf_common::identity::Edipi;
use pf_common::job::ColorMode;
use pf_common::policy::QuotaStatus;
use serde::{Deserialize, Serialize};

use crate::error::AccountingError;

/// A user's quota counter for a billing period.
///
/// **NIST 800-53 Rev 5:** AU-12 — Audit Record Generation
/// Quota updates and exceedances are auditable events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCounter {
    /// The user whose quota is tracked.
    pub edipi: Edipi,
    /// Total page limit for the period.
    pub page_limit: u32,
    /// Pages consumed so far in the period.
    pub pages_used: u32,
    /// Color page limit for the period.
    pub color_page_limit: u32,
    /// Color pages consumed so far in the period.
    pub color_pages_used: u32,
    /// Start of the current billing period.
    pub period_start: DateTime<Utc>,
    /// End of the current billing period.
    pub period_end: DateTime<Utc>,
    /// Burst pages consumed above the standard limit (if burst is allowed).
    pub burst_pages_used: u32,
    /// Maximum burst pages allowed above the standard limit.
    pub burst_limit: u32,
}

impl QuotaCounter {
    /// Convert to the shared `QuotaStatus` type used by `pf-policy-engine`.
    #[must_use]
    pub fn to_quota_status(&self) -> QuotaStatus {
        QuotaStatus {
            limit: self.page_limit,
            used: self.pages_used,
            color_limit: self.color_page_limit,
            color_used: self.color_pages_used,
        }
    }

    /// Check whether the user can print the requested number of pages.
    ///
    /// Considers both the standard limit and burst allowance.
    #[must_use]
    pub fn can_print(&self, pages: u32, is_color: bool) -> bool {
        let effective_limit = self.page_limit + self.burst_limit;
        let total_used = self.pages_used + self.burst_pages_used;

        if total_used + pages > effective_limit {
            return false;
        }

        if is_color && self.color_pages_used + pages > self.color_page_limit {
            return false;
        }

        true
    }

    /// Record page consumption for a completed job.
    ///
    /// If the user's standard quota is exceeded, pages spill into the burst
    /// counter (up to `burst_limit`).
    ///
    /// # Errors
    ///
    /// Returns [`AccountingError::QuotaExceeded`] if the total consumption
    /// (including burst) would exceed the effective limit.
    pub fn record_usage(
        &mut self,
        pages: u32,
        color_mode: ColorMode,
    ) -> Result<QuotaUsageResult, AccountingError> {
        let effective_limit = self.page_limit + self.burst_limit;
        let current_total = self.pages_used + self.burst_pages_used;

        if current_total + pages > effective_limit {
            return Err(AccountingError::QuotaExceeded {
                limit: effective_limit,
                used: current_total,
                requested: pages,
            });
        }

        let is_color = color_mode == ColorMode::Color;

        // Track color pages
        if is_color {
            self.color_pages_used += pages;
        }

        // Fill standard quota first, then burst
        let standard_remaining = self.page_limit.saturating_sub(self.pages_used);
        if pages <= standard_remaining {
            self.pages_used += pages;
        } else {
            let burst_pages = pages - standard_remaining;
            self.pages_used = self.page_limit;
            self.burst_pages_used += burst_pages;
        }

        let new_total = self.pages_used + self.burst_pages_used;

        Ok(QuotaUsageResult {
            pages_consumed: pages,
            standard_remaining: self.page_limit.saturating_sub(self.pages_used),
            burst_remaining: self.burst_limit.saturating_sub(self.burst_pages_used),
            color_remaining: self.color_page_limit.saturating_sub(self.color_pages_used),
            quota_exceeded_warning: new_total >= self.page_limit,
        })
    }

    /// Reset the counter for a new billing period.
    pub fn reset(&mut self, new_period_start: DateTime<Utc>, new_period_end: DateTime<Utc>) {
        self.pages_used = 0;
        self.color_pages_used = 0;
        self.burst_pages_used = 0;
        self.period_start = new_period_start;
        self.period_end = new_period_end;
    }
}

/// Result of recording page usage against a quota counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaUsageResult {
    /// Number of pages consumed by this operation.
    pub pages_consumed: u32,
    /// Remaining standard pages after this operation.
    pub standard_remaining: u32,
    /// Remaining burst pages after this operation.
    pub burst_remaining: u32,
    /// Remaining color pages after this operation.
    pub color_remaining: u32,
    /// Whether the standard quota has been exceeded (using burst).
    pub quota_exceeded_warning: bool,
}

/// Calculate the next quota reset date given a reset day of month.
///
/// If today is before the reset day, returns the reset day this month.
/// If today is on or after the reset day, returns the reset day next month.
/// Clamps to the last day of the month if the reset day exceeds the number
/// of days in that month (e.g., day 31 in February becomes 28/29).
///
/// # Errors
///
/// Returns [`AccountingError::InvalidChargebackPeriod`] if the reset day
/// is not in the range 1-28.
pub fn next_reset_date(today: NaiveDate, reset_day: u8) -> Result<NaiveDate, AccountingError> {
    if !(1..=28).contains(&reset_day) {
        return Err(AccountingError::InvalidChargebackPeriod {
            message: format!("reset day must be 1-28, got {reset_day}"),
        });
    }

    let day = u32::from(reset_day);

    // Try this month first
    if today.day() < day {
        if let Some(date) = NaiveDate::from_ymd_opt(today.year(), today.month(), day) {
            return Ok(date);
        }
    }

    // Otherwise, next month
    let (year, month) = if today.month() == 12 {
        (today.year() + 1, 1)
    } else {
        (today.year(), today.month() + 1)
    };

    NaiveDate::from_ymd_opt(year, month, day)
        .or_else(|| {
            // Clamp to last day of month
            NaiveDate::from_ymd_opt(year, month, 28)
        })
        .ok_or_else(|| AccountingError::InvalidChargebackPeriod {
            message: format!("cannot compute reset date for {year}-{month}-{day}"),
        })
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn test_counter() -> QuotaCounter {
        QuotaCounter {
            edipi: Edipi::new("1234567890").unwrap(),
            page_limit: 500,
            pages_used: 0,
            color_page_limit: 100,
            color_pages_used: 0,
            period_start: Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap(),
            period_end: Utc.with_ymd_and_hms(2026, 3, 31, 23, 59, 59).unwrap(),
            burst_pages_used: 0,
            burst_limit: 50,
        }
    }

    #[test]
    fn can_print_within_quota() {
        let counter = test_counter();
        assert!(counter.can_print(100, false));
    }

    #[test]
    fn can_print_with_burst() {
        let mut counter = test_counter();
        counter.pages_used = 490;
        // 490 + 20 = 510 <= 500 + 50 = 550
        assert!(counter.can_print(20, false));
    }

    #[test]
    fn cannot_print_exceeds_burst() {
        let mut counter = test_counter();
        counter.pages_used = 500;
        counter.burst_pages_used = 40;
        // 540 + 20 = 560 > 550
        assert!(!counter.can_print(20, false));
    }

    #[test]
    fn cannot_print_color_exceeds_color_quota() {
        let mut counter = test_counter();
        counter.color_pages_used = 95;
        assert!(!counter.can_print(10, true));
    }

    #[test]
    fn record_usage_standard() {
        let mut counter = test_counter();
        let result = counter.record_usage(10, ColorMode::Grayscale).unwrap();

        assert_eq!(result.pages_consumed, 10);
        assert_eq!(counter.pages_used, 10);
        assert_eq!(counter.burst_pages_used, 0);
        assert_eq!(result.standard_remaining, 490);
        assert!(!result.quota_exceeded_warning);
    }

    #[test]
    fn record_usage_spills_to_burst() {
        let mut counter = test_counter();
        counter.pages_used = 495;
        let result = counter.record_usage(10, ColorMode::Grayscale).unwrap();

        assert_eq!(counter.pages_used, 500);
        assert_eq!(counter.burst_pages_used, 5);
        assert_eq!(result.standard_remaining, 0);
        assert_eq!(result.burst_remaining, 45);
        assert!(result.quota_exceeded_warning);
    }

    #[test]
    fn record_usage_tracks_color() {
        let mut counter = test_counter();
        let result = counter.record_usage(10, ColorMode::Color).unwrap();

        assert_eq!(counter.color_pages_used, 10);
        assert_eq!(result.color_remaining, 90);
    }

    #[test]
    fn record_usage_rejects_over_burst() {
        let mut counter = test_counter();
        counter.pages_used = 500;
        counter.burst_pages_used = 50;
        let result = counter.record_usage(1, ColorMode::Grayscale);
        assert!(result.is_err());
    }

    #[test]
    fn nist_au12_quota_exceeded_produces_error() {
        // NIST 800-53 Rev 5: AU-12 — Audit Record Generation
        // QuotaExceeded is an auditable event.
        let mut counter = test_counter();
        counter.pages_used = 500;
        counter.burst_pages_used = 50;
        let err = counter.record_usage(1, ColorMode::Grayscale).unwrap_err();
        assert!(matches!(err, AccountingError::QuotaExceeded { .. }));
    }

    #[test]
    fn reset_clears_counters() {
        let mut counter = test_counter();
        counter.pages_used = 300;
        counter.color_pages_used = 50;
        counter.burst_pages_used = 10;

        let new_start = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let new_end = Utc.with_ymd_and_hms(2026, 4, 30, 23, 59, 59).unwrap();
        counter.reset(new_start, new_end);

        assert_eq!(counter.pages_used, 0);
        assert_eq!(counter.color_pages_used, 0);
        assert_eq!(counter.burst_pages_used, 0);
        assert_eq!(counter.period_start, new_start);
    }

    #[test]
    fn to_quota_status_maps_correctly() {
        let mut counter = test_counter();
        counter.pages_used = 100;
        counter.color_pages_used = 25;

        let status = counter.to_quota_status();
        assert_eq!(status.limit, 500);
        assert_eq!(status.used, 100);
        assert_eq!(status.color_limit, 100);
        assert_eq!(status.color_used, 25);
        assert_eq!(status.remaining(), 400);
    }

    #[test]
    fn next_reset_date_this_month() {
        let today = NaiveDate::from_ymd_opt(2026, 3, 10).unwrap();
        let reset = next_reset_date(today, 15).unwrap();
        assert_eq!(reset, NaiveDate::from_ymd_opt(2026, 3, 15).unwrap());
    }

    #[test]
    fn next_reset_date_next_month() {
        let today = NaiveDate::from_ymd_opt(2026, 3, 20).unwrap();
        let reset = next_reset_date(today, 15).unwrap();
        assert_eq!(reset, NaiveDate::from_ymd_opt(2026, 4, 15).unwrap());
    }

    #[test]
    fn next_reset_date_rejects_invalid_day() {
        let today = NaiveDate::from_ymd_opt(2026, 3, 10).unwrap();
        assert!(next_reset_date(today, 0).is_err());
        assert!(next_reset_date(today, 29).is_err());
    }

    #[test]
    fn next_reset_date_wraps_year() {
        let today = NaiveDate::from_ymd_opt(2026, 12, 20).unwrap();
        let reset = next_reset_date(today, 15).unwrap();
        assert_eq!(reset, NaiveDate::from_ymd_opt(2027, 1, 15).unwrap());
    }
}
