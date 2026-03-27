// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! Platform-specific process resource querying.

use shadi_sandbox::ProcessResources;

/// Query resource usage for a process by PID.
///
/// Returns `None` if the process does not exist or the platform does not
/// support resource querying.
#[cfg(target_os = "macos")]
pub(crate) fn query_process_resources(pid: u32) -> Option<ProcessResources> {
    // proc_pidinfo with PROC_PIDTASKINFO is a stable macOS API
    // exported by libSystem.B.dylib.
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct proc_taskinfo {
        pti_virtual_size: u64,
        pti_resident_size: u64,
        pti_total_user: u64,
        pti_total_system: u64,
        pti_threads_user: u64,
        pti_threads_system: u64,
        pti_policy: i32,
        pti_faults: i32,
        pti_pageins: i32,
        pti_cow_faults: i32,
        pti_messages_sent: i32,
        pti_messages_received: i32,
        pti_syscalls_mach: i32,
        pti_syscalls_unix: i32,
        pti_csw: i32,
        pti_threadnum: i32,
        pti_numrunning: i32,
        pti_priority: i32,
    }

    const PROC_PIDTASKINFO: i32 = 4;

    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: i32,
        ) -> i32;
    }

    let mut info: proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<proc_taskinfo>() as i32;

    let ret = unsafe {
        proc_pidinfo(
            pid as i32,
            PROC_PIDTASKINFO,
            0,
            (&mut info as *mut proc_taskinfo).cast(),
            size,
        )
    };

    if ret <= 0 {
        return None;
    }

    Some(ProcessResources {
        pid,
        rss_bytes: Some(info.pti_resident_size),
        virtual_bytes: Some(info.pti_virtual_size),
        cpu_user_ms: Some(info.pti_total_user / 1_000_000),
        cpu_system_ms: Some(info.pti_total_system / 1_000_000),
        thread_count: Some(info.pti_threadnum as u32),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn query_process_resources(pid: u32) -> Option<ProcessResources> {
    let statm = std::fs::read_to_string(format!("/proc/{}/statm", pid)).ok()?;
    let fields: Vec<&str> = statm.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let virtual_pages: u64 = fields[0].parse().ok()?;
    let rss_pages: u64 = fields[1].parse().ok()?;

    // CPU times from /proc/{pid}/stat (fields 14=utime, 15=stime in clock ticks).
    let (cpu_user_ms, cpu_system_ms) = std::fs::read_to_string(format!("/proc/{}/stat", pid))
        .ok()
        .and_then(|stat| {
            let parts: Vec<&str> = stat.split_whitespace().collect();
            if parts.len() < 15 {
                return None;
            }
            let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
            let utime: u64 = parts[13].parse().ok()?;
            let stime: u64 = parts[14].parse().ok()?;
            Some((
                Some(utime * 1000 / ticks_per_sec),
                Some(stime * 1000 / ticks_per_sec),
            ))
        })
        .unwrap_or((None, None));

    // Thread count from /proc/{pid}/status.
    let thread_count = std::fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()
        .and_then(|status| {
            for line in status.lines() {
                if let Some(value) = line.strip_prefix("Threads:") {
                    return value.trim().parse().ok();
                }
            }
            None
        });

    Some(ProcessResources {
        pid,
        rss_bytes: Some(rss_pages * page_size),
        virtual_bytes: Some(virtual_pages * page_size),
        cpu_user_ms,
        cpu_system_ms,
        thread_count,
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn query_process_resources(_pid: u32) -> Option<ProcessResources> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_own_process_returns_some() {
        let pid = std::process::id();
        let resources = query_process_resources(pid);
        // Should succeed for our own process on supported platforms.
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let r = resources.expect("should return resources for own process");
            assert_eq!(r.pid, pid);
            assert!(r.rss_bytes.unwrap() > 0);
            assert!(r.virtual_bytes.unwrap() > 0);
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            assert!(resources.is_none());
        }
    }

    #[test]
    fn query_nonexistent_process_returns_none() {
        // PID 0 is the kernel scheduler, we shouldn't be able to query it
        // (or it doesn't exist as a user process).
        let resources = query_process_resources(999_999_999);
        assert!(resources.is_none());
    }
}
