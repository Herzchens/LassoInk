//! Whole-process CPU observations for a local diagnostic session.

use std::time::Instant;
use windows_sys::Win32::{
    Foundation::{FILETIME, GetLastError},
    System::Threading::{GetCurrentProcess, GetProcessTimes},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileTimeWords {
    pub low: u32,
    pub high: u32,
}

impl FileTimeWords {
    fn from_raw(value: FILETIME) -> Self {
        Self {
            low: value.dwLowDateTime,
            high: value.dwHighDateTime,
        }
    }

    fn ticks_100ns(self) -> u64 {
        (u64::from(self.high) << 32) | u64::from(self.low)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessCpuSnapshot {
    pub app_elapsed_ns: u128,
    pub user: Option<FileTimeWords>,
    pub kernel: Option<FileTimeWords>,
    pub win32_error: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProcessCpuUnavailableReason {
    StartSnapshotFailed { win32_error: u32 },
    EndSnapshotFailed { win32_error: u32 },
    SnapshotValuesUnavailable,
    AppClockRegressed,
    ZeroMeasurementInterval,
    ProcessTimeRegressed,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProcessCpuMeasurement {
    pub start: ProcessCpuSnapshot,
    pub end: ProcessCpuSnapshot,
    pub app_interval_ns: Option<u128>,
    pub user_delta_100ns: Option<u128>,
    pub kernel_delta_100ns: Option<u128>,
    pub core_equivalent_percent: Option<f64>,
    pub unavailable_reason: Option<ProcessCpuUnavailableReason>,
}

pub(crate) const PROCESS_CPU_SCOPE: &str = "whole process/all threads; includes event loop and session record I/O; excludes CPU/footer row and final sync/publish; not isolated capture or driver CPU";

pub(crate) fn snapshot(app_clock_origin: Instant) -> ProcessCpuSnapshot {
    let mut creation_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: GetCurrentProcess returns the process pseudo-handle, which is not
    // owned and must not be closed. All output pointers below refer to live,
    // correctly aligned local FILETIME values for the duration of the call.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `process` is the current-process pseudo-handle and each output
    // pointer is valid, writable storage of the exact Win32 FILETIME layout.
    let succeeded = unsafe {
        GetProcessTimes(
            process,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )
    };
    let win32_error = if succeeded == 0 {
        // SAFETY: This reads the thread's error code immediately after the
        // failed Win32 call; no clock or formatting work has run in between.
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let app_elapsed_ns = app_clock_origin.elapsed().as_nanos();
    if let Some(win32_error) = win32_error {
        ProcessCpuSnapshot {
            app_elapsed_ns,
            user: None,
            kernel: None,
            win32_error: Some(win32_error),
        }
    } else {
        ProcessCpuSnapshot {
            app_elapsed_ns,
            user: Some(FileTimeWords::from_raw(user_time)),
            kernel: Some(FileTimeWords::from_raw(kernel_time)),
            win32_error: None,
        }
    }
}

pub(crate) fn measure(start: ProcessCpuSnapshot, end: ProcessCpuSnapshot) -> ProcessCpuMeasurement {
    let mut measurement = ProcessCpuMeasurement {
        app_interval_ns: end.app_elapsed_ns.checked_sub(start.app_elapsed_ns),
        start,
        end,
        user_delta_100ns: None,
        kernel_delta_100ns: None,
        core_equivalent_percent: None,
        unavailable_reason: None,
    };

    let failure = if let Some(win32_error) = measurement.start.win32_error {
        Some(ProcessCpuUnavailableReason::StartSnapshotFailed { win32_error })
    } else if let Some(win32_error) = measurement.end.win32_error {
        Some(ProcessCpuUnavailableReason::EndSnapshotFailed { win32_error })
    } else if measurement.app_interval_ns.is_none() {
        Some(ProcessCpuUnavailableReason::AppClockRegressed)
    } else if measurement.app_interval_ns == Some(0) {
        Some(ProcessCpuUnavailableReason::ZeroMeasurementInterval)
    } else {
        None
    };
    if let Some(reason) = failure {
        measurement.unavailable_reason = Some(reason);
        return measurement;
    }

    let Some(start_user) = measurement.start.user.map(FileTimeWords::ticks_100ns) else {
        measurement.unavailable_reason =
            Some(ProcessCpuUnavailableReason::SnapshotValuesUnavailable);
        return measurement;
    };
    let Some(end_user) = measurement.end.user.map(FileTimeWords::ticks_100ns) else {
        measurement.unavailable_reason =
            Some(ProcessCpuUnavailableReason::SnapshotValuesUnavailable);
        return measurement;
    };
    let Some(start_kernel) = measurement.start.kernel.map(FileTimeWords::ticks_100ns) else {
        measurement.unavailable_reason =
            Some(ProcessCpuUnavailableReason::SnapshotValuesUnavailable);
        return measurement;
    };
    let Some(end_kernel) = measurement.end.kernel.map(FileTimeWords::ticks_100ns) else {
        measurement.unavailable_reason =
            Some(ProcessCpuUnavailableReason::SnapshotValuesUnavailable);
        return measurement;
    };
    let (Some(user_delta), Some(kernel_delta)) = (
        end_user.checked_sub(start_user),
        end_kernel.checked_sub(start_kernel),
    ) else {
        measurement.unavailable_reason = Some(ProcessCpuUnavailableReason::ProcessTimeRegressed);
        return measurement;
    };
    measurement.user_delta_100ns = Some(u128::from(user_delta));
    measurement.kernel_delta_100ns = Some(u128::from(kernel_delta));
    let total_ticks = u128::from(user_delta) + u128::from(kernel_delta);
    let app_interval_ns = measurement.app_interval_ns.expect("checked above");
    measurement.core_equivalent_percent =
        Some((total_ticks as f64 * 10_000.0) / app_interval_ns as f64);
    measurement
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(ticks: u64) -> FileTimeWords {
        FileTimeWords {
            low: ticks as u32,
            high: (ticks >> 32) as u32,
        }
    }

    fn snapshot(app_elapsed_ns: u128, user_ticks: u64, kernel_ticks: u64) -> ProcessCpuSnapshot {
        ProcessCpuSnapshot {
            app_elapsed_ns,
            user: Some(words(user_ticks)),
            kernel: Some(words(kernel_ticks)),
            win32_error: None,
        }
    }

    #[test]
    fn process_cpu_ratio_is_whole_process_core_equivalent_and_can_exceed_100_percent() {
        // 2 seconds of aggregate process CPU over a 1 second app interval.
        let measured = measure(
            snapshot(0, 10_000_000, 10_000_000),
            snapshot(1_000_000_000, 20_000_000, 20_000_000),
        );
        assert_eq!(measured.user_delta_100ns, Some(10_000_000));
        assert_eq!(measured.kernel_delta_100ns, Some(10_000_000));
        assert_eq!(measured.core_equivalent_percent, Some(200.0));
        assert_eq!(measured.unavailable_reason, None);
    }

    #[test]
    fn process_cpu_failed_snapshots_have_null_metrics_and_raw_error() {
        let start = ProcessCpuSnapshot {
            app_elapsed_ns: 100,
            user: None,
            kernel: None,
            win32_error: Some(5),
        };
        let measured = measure(start, snapshot(200, 1, 2));
        assert_eq!(measured.core_equivalent_percent, None);
        assert_eq!(measured.user_delta_100ns, None);
        assert_eq!(
            measured.unavailable_reason,
            Some(ProcessCpuUnavailableReason::StartSnapshotFailed { win32_error: 5 })
        );
        assert_eq!(measured.start.app_elapsed_ns, 100);
    }

    #[test]
    fn process_cpu_nulls_nonmonotonic_or_zero_wall_intervals() {
        let regressed = measure(snapshot(200, 10, 10), snapshot(100, 20, 20));
        assert_eq!(regressed.core_equivalent_percent, None);
        assert_eq!(
            regressed.unavailable_reason,
            Some(ProcessCpuUnavailableReason::AppClockRegressed)
        );

        let zero = measure(snapshot(100, 10, 10), snapshot(100, 20, 20));
        assert_eq!(zero.core_equivalent_percent, None);
        assert_eq!(
            zero.unavailable_reason,
            Some(ProcessCpuUnavailableReason::ZeroMeasurementInterval)
        );

        let cpu_regressed = measure(snapshot(100, 20, 10), snapshot(200, 10, 20));
        assert_eq!(cpu_regressed.core_equivalent_percent, None);
        assert_eq!(
            cpu_regressed.unavailable_reason,
            Some(ProcessCpuUnavailableReason::ProcessTimeRegressed)
        );
    }
}
