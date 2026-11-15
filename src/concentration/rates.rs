use super::{accumulate::RequestConcentration, types::*};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

impl RequestConcentration {
    pub(super) fn observe_minute(&mut self, timestamp: Option<DateTime<Utc>>, status: Option<u16>) {
        let Some(timestamp) = timestamp else {
            self.observations_without_timestamp += 1;
            return;
        };
        let minute_epoch = timestamp.timestamp().div_euclid(60);
        if Self::track_minute_bucket(
            &mut self.minute_buckets,
            &mut self.minute_buckets_beyond_cap,
            self.limits.max_minute_buckets,
            minute_epoch,
        ) {
            record_status_class(
                self.status_minute_buckets.entry(minute_epoch).or_default(),
                status,
            );
        }
        Self::track_rate_windows(
            &self.rate_window_seconds,
            &mut self.rate_buckets,
            &mut self.rate_buckets_beyond_cap,
            self.limits.max_minute_buckets,
            timestamp,
        );
        Self::track_status_rate_windows(
            &self.rate_window_seconds,
            &self.rate_buckets,
            &mut self.status_rate_buckets,
            timestamp,
            status,
        );
    }

    pub(super) fn request_rate(&self) -> (Option<u64>, Option<f64>, Option<f64>) {
        Self::request_rate_for(&self.minute_buckets)
    }

    pub(super) fn track_minute_bucket(
        buckets: &mut BTreeMap<i64, u64>,
        beyond_cap: &mut u64,
        maximum: usize,
        minute_epoch: i64,
    ) -> bool {
        if !buckets.contains_key(&minute_epoch) && buckets.len() >= maximum {
            *beyond_cap += 1;
            return false;
        }
        *buckets.entry(minute_epoch).or_default() += 1;
        true
    }

    pub(super) fn minute_series(buckets: &BTreeMap<i64, u64>) -> Vec<MinuteRequestCount> {
        buckets
            .iter()
            .map(|(minute_epoch, requests)| MinuteRequestCount {
                minute_epoch: *minute_epoch,
                requests: *requests,
            })
            .collect()
    }

    pub(super) fn status_minute_series(
        buckets: &BTreeMap<i64, StatusClassCounts>,
    ) -> Vec<StatusClassMinuteCount> {
        buckets
            .iter()
            .map(|(minute_epoch, counts)| StatusClassMinuteCount {
                minute_epoch: *minute_epoch,
                informational: counts.informational,
                success: counts.success,
                redirection: counts.redirection,
                client_error: counts.client_error,
                server_error: counts.server_error,
            })
            .collect()
    }

    pub(super) fn request_rate_for(
        buckets: &BTreeMap<i64, u64>,
    ) -> (Option<u64>, Option<f64>, Option<f64>) {
        if buckets.is_empty() {
            return (None, None, None);
        }
        let mut values = buckets.values().copied().collect::<Vec<_>>();
        values.sort_unstable();
        let peak = *values.last().expect("checked non-empty minute buckets");
        let middle = values.len() / 2;
        let median = if values.len().is_multiple_of(2) {
            (values[middle - 1] as f64 + values[middle] as f64) / 2.0
        } else {
            values[middle] as f64
        };
        let ratio = (median != 0.0).then(|| peak as f64 / median);
        (Some(peak), Some(median), ratio)
    }

    pub(super) fn track_rate_windows(
        widths: &[u64],
        rate_buckets: &mut BTreeMap<u64, BTreeMap<i64, u64>>,
        beyond_caps: &mut BTreeMap<u64, u64>,
        maximum: usize,
        timestamp: DateTime<Utc>,
    ) {
        for width in widths {
            let Ok(width) = i64::try_from(*width) else {
                continue;
            };
            let bucket = timestamp.timestamp().div_euclid(width);
            Self::track_minute_bucket(
                rate_buckets
                    .get_mut(&u64::try_from(width).expect("positive configured rate width"))
                    .expect("all configured rate widths have a bucket map"),
                beyond_caps
                    .get_mut(&u64::try_from(width).expect("positive configured rate width"))
                    .expect("all configured rate widths have a cap counter"),
                maximum,
                bucket,
            );
        }
    }

    fn track_status_rate_windows(
        widths: &[u64],
        admitted_rate_buckets: &BTreeMap<u64, BTreeMap<i64, u64>>,
        status_buckets: &mut BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
        timestamp: DateTime<Utc>,
        status: Option<u16>,
    ) {
        for width in widths {
            let Ok(width_i64) = i64::try_from(*width) else {
                continue;
            };
            let bucket = timestamp.timestamp().div_euclid(width_i64);
            if admitted_rate_buckets
                .get(width)
                .is_some_and(|buckets| buckets.contains_key(&bucket))
            {
                record_status_class(
                    status_buckets
                        .get_mut(width)
                        .expect("all configured rate widths have a status map")
                        .entry(bucket)
                        .or_default(),
                    status,
                );
            }
        }
    }

    pub(super) fn windowed_rate_summaries(
        &self,
        rate_buckets: &BTreeMap<u64, BTreeMap<i64, u64>>,
        beyond_caps: &BTreeMap<u64, u64>,
        observations_without_timestamp: u64,
    ) -> Vec<WindowedRequestRateSummary> {
        self.rate_window_seconds
            .iter()
            .map(|seconds| {
                let (peak, median, ratio) = Self::request_rate_for(
                    rate_buckets
                        .get(seconds)
                        .expect("all configured rate widths have a bucket map"),
                );
                WindowedRequestRateSummary {
                    bucket_width_seconds: *seconds,
                    peak_requests: peak,
                    median_requests: median,
                    peak_to_median_ratio: ratio,
                    observations_without_timestamp,
                    observations_beyond_bucket_cap: *beyond_caps.get(seconds).unwrap_or(&0),
                }
            })
            .collect()
    }

    pub(super) fn windowed_response_outcome_summaries(
        &self,
        status_buckets: &BTreeMap<u64, BTreeMap<i64, StatusClassCounts>>,
        beyond_caps: &BTreeMap<u64, u64>,
        observations_without_timestamp: u64,
    ) -> Vec<WindowedResponseOutcomeSummary> {
        self.rate_window_seconds
            .iter()
            .map(|seconds| {
                let buckets = status_buckets
                    .get(seconds)
                    .expect("all configured rate widths have a status map");
                let mut minimum_success_share: Option<f64> = None;
                let mut maximum_server_error_share: Option<f64> = None;
                let mut eligible_buckets = 0;
                let mut buckets_below_minimum = 0;
                let mut buckets_without_status = 0;
                let mut minimum_success_bucket_start = None;
                let mut maximum_server_error_bucket_start = None;
                let mut minimum_fraction: Option<(u64, u64)> = None;
                let mut maximum_fraction: Option<(u64, u64)> = None;
                let mut buckets_below_success_threshold = 0;
                // BTreeMap order is chronological. Strict rational comparison
                // retains the earliest tied bucket without floating-point ties.
                for (&bucket, counts) in buckets {
                    let total = counts.total_observations();
                    if total == counts.unavailable {
                        buckets_without_status += 1;
                        continue;
                    }
                    if total < self.response_bucket_minimum_requests {
                        buckets_below_minimum += 1;
                        continue;
                    }
                    eligible_buckets += 1;
                    let success = share(counts.success, total);
                    let server_error = share(counts.server_error, total);
                    let start = bucket
                        .checked_mul(*seconds as i64)
                        .and_then(|epoch| DateTime::from_timestamp(epoch, 0));
                    if minimum_fraction.is_none_or(|(n, d)| {
                        u128::from(counts.success) * u128::from(d)
                            < u128::from(n) * u128::from(total)
                    }) {
                        minimum_fraction = Some((counts.success, total));
                        minimum_success_share = Some(success);
                        minimum_success_bucket_start = start;
                    }
                    if maximum_fraction.is_none_or(|(n, d)| {
                        u128::from(counts.server_error) * u128::from(d)
                            > u128::from(n) * u128::from(total)
                    }) {
                        maximum_fraction = Some((counts.server_error, total));
                        maximum_server_error_share = Some(server_error);
                        maximum_server_error_bucket_start = start;
                    }
                    if u128::from(counts.success) * 100
                        < u128::from(total)
                            * u128::from(self.response_success_share_threshold_percent)
                    {
                        buckets_below_success_threshold += 1;
                    }
                }
                WindowedResponseOutcomeSummary {
                    bucket_width_seconds: *seconds,
                    minimum_requests_per_bucket: self.response_bucket_minimum_requests,
                    eligible_buckets,
                    buckets_below_minimum,
                    minimum_success_share,
                    maximum_server_error_share,
                    minimum_success_bucket_start,
                    maximum_server_error_bucket_start,
                    success_share_threshold_percent: Some(
                        self.response_success_share_threshold_percent,
                    ),
                    buckets_below_success_threshold: (eligible_buckets > 0)
                        .then_some(buckets_below_success_threshold),
                    buckets_without_status,
                    observations_without_timestamp,
                    observations_beyond_bucket_cap: *beyond_caps.get(seconds).unwrap_or(&0),
                }
            })
            .collect()
    }

    pub(super) fn share(&self, count: u64) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            count as f64 / self.total_requests as f64
        }
    }
}

pub(super) fn normalize_rate_windows(widths: &[u64]) -> Vec<u64> {
    let mut widths = widths
        .iter()
        .copied()
        .filter(|width| *width != 0 && *width <= i64::MAX as u64)
        .collect::<Vec<_>>();
    widths.sort_unstable();
    widths.dedup();
    widths
}

pub(super) fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

pub(super) fn response_outcome_summary(counts: &StatusClassCounts) -> ResponseOutcomeSummary {
    let total = counts.total_observations();
    ResponseOutcomeSummary {
        counts: counts.clone(),
        success_share: share(counts.success, total),
        redirection_share: share(counts.redirection, total),
        ordinary_client_error_share: share(counts.ordinary_client_error(), total),
        client_closed_request_499_share: share(counts.client_closed_request_499, total),
        server_error_share: share(counts.server_error, total),
    }
}

pub(crate) fn record_status_class(counts: &mut StatusClassCounts, status: Option<u16>) {
    match status {
        Some(100..=199) => counts.informational += 1,
        Some(200..=299) => counts.success += 1,
        Some(300..=399) => counts.redirection += 1,
        Some(499) => {
            counts.client_error += 1;
            counts.client_closed_request_499 += 1;
        }
        Some(400..=498) => counts.client_error += 1,
        Some(500..=599) => counts.server_error += 1,
        Some(_) => counts.other += 1,
        None => counts.unavailable += 1,
    }
}
