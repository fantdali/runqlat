#![no_std]
#![no_main]
#![allow(static_mut_refs)]

#[allow(
    clippy::all,
    dead_code,
    improper_ctypes_definitions,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes,
    unsafe_op_in_unsafe_fn,
)]
#[rustfmt::skip]
mod vmlinux;

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{map, raw_tracepoint},
    maps::HashMap,
    programs::RawTracePointContext,
};

use runqlat_common::{Histogram, MAX_SLOTS};
use vmlinux::task_struct;

/// Max number of tracked processes and threads
const MAX_ENTRIES: u32 = 2048;

const TASK_RUNNING: u32 = 0;

// NOTE:
// tutorial https://eunomia.dev/en/tutorials/9-runqlat/
// pid vs tgid in task_struct https://marselester.com/linux-process.html

/// Tracked processes.
/// tgid (process id) -> tracked
#[map(name = "PID")]
static mut PID: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(MAX_ENTRIES, 0);

/// Start timestamps of threads.
/// pid (thread id) -> start timestamp (ns)
#[map(name = "START")]
static mut START: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(MAX_ENTRIES, 0);

/// Histograms of run queue latencies.
/// tgid (process id) -> histogram of run queue latencies counts in log2 buckets (us)
#[map(name = "HIST")]
static mut HIST: HashMap<u32, Histogram> =
    HashMap::<u32, Histogram>::with_max_entries(MAX_ENTRIES, 0);

// https://elixir.bootlin.com/linux/v6.2.16/source/include/trace/events/sched.h#L178
#[raw_tracepoint(tracepoint = "sched_wakeup")]
pub fn sched_wakeup(ctx: RawTracePointContext) -> i32 {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    if task.is_null() {
        return 0;
    }

    let tgid = match unsafe { bpf_probe_read_kernel(&(*task).tgid) } {
        Ok(tgid) => tgid as u32,
        Err(_) => return 0,
    };
    if unsafe { PID.get(&tgid).is_none() } {
        return 0;
    }

    let pid = match unsafe { bpf_probe_read_kernel(&(*task).pid) } {
        Ok(pid) => pid as u32,
        Err(_) => return 0,
    };
    save_start_ts(pid);
    0
}

// https://elixir.bootlin.com/linux/v6.2.16/source/include/trace/events/sched.h#L185
#[raw_tracepoint(tracepoint = "sched_wakeup_new")]
pub fn sched_wakeup_new(ctx: RawTracePointContext) -> i32 {
    let task: *const task_struct = unsafe { ctx.arg(0) };
    if task.is_null() {
        return 0;
    }

    let tgid = match unsafe { bpf_probe_read_kernel(&(*task).tgid) } {
        Ok(tgid) => tgid as u32,
        Err(_) => return 0,
    };
    if unsafe { PID.get(&tgid).is_none() } {
        return 0;
    }

    let pid = match unsafe { bpf_probe_read_kernel(&(*task).pid) } {
        Ok(pid) => pid as u32,
        Err(_) => return 0,
    };
    save_start_ts(pid);
    0
}

// https://elixir.bootlin.com/linux/v6.2.16/source/include/trace/events/sched.h#L222
#[raw_tracepoint(tracepoint = "sched_switch")]
pub fn sched_switch(ctx: RawTracePointContext) -> i32 {
    let _ = try_sched_switch(ctx);
    0
}

#[inline(always)]
fn try_sched_switch(ctx: RawTracePointContext) -> Result<(), i64> {
    let prev: *const task_struct = unsafe { ctx.arg(1) };
    let next: *const task_struct = unsafe { ctx.arg(2) };
    if prev.is_null() || next.is_null() {
        return Ok(());
    }

    // NOTE: bpf_probe_read_kernel used to read fields from kernel memory of raw_tracepoint args
    let prev_pid = unsafe { bpf_probe_read_kernel(&(*prev).tgid)? as u32 };
    let prev_tgid = unsafe { bpf_probe_read_kernel(&(*prev).tgid)? as u32 };
    let prev_state = unsafe { bpf_probe_read_kernel(&(*prev).__state)? };

    // if prev.state running and prev.tgid tracked -> save start_ts of prev.pid
    if prev_state == TASK_RUNNING && unsafe { PID.get(&prev_tgid).is_some() } {
        save_start_ts(prev_pid);
    }

    let next_tgid = unsafe { bpf_probe_read_kernel(&(*next).tgid)? as u32 };

    // if next.tgid not tracked -> return
    if unsafe { PID.get(&next_tgid).is_none() } {
        return Ok(());
    }

    let next_pid = unsafe { bpf_probe_read_kernel(&(*next).pid)? as u32 };

    // get next.pid saved start_ts
    let start_ts = match unsafe { START.get(&next_pid) } {
        Some(ts) => *ts,
        None => return Ok(()),
    };

    // calculate delta_us = now_ts - start_ts
    let now_ts = unsafe { bpf_ktime_get_ns() };
    if now_ts < start_ts {
        let _ = unsafe { START.remove(&next_pid) };
        return Ok(());
    }
    let delta_us = (now_ts - start_ts) / 1000;

    // calculate histogram slot for delta_us
    let mut slot = log2_u64(delta_us) as usize;
    if slot >= MAX_SLOTS {
        slot = MAX_SLOTS - 1;
    }

    // increment histogram slot of next.tgid
    if let Some(hist) = unsafe { HIST.get_ptr_mut(&next_tgid) } {
        unsafe {
            (*hist)[slot] = (*hist)[slot].saturating_add(1);
        }
    } else {
        let mut hist = [0; MAX_SLOTS];
        hist[slot] = 1;
        let _ = unsafe { HIST.insert(&next_tgid, &hist, 0) };
    }

    // remove next.pid start_ts
    let _ = unsafe { START.remove(&next_pid) };

    Ok(())
}

// -- helpers --

#[inline(always)]
fn save_start_ts(pid: u32) {
    if pid == 0 {
        return;
    }
    let ts = unsafe { bpf_ktime_get_ns() } as u64;
    let _ = unsafe { START.insert(&pid, &ts, 0) };
}

#[inline(always)]
fn log2_u64(v: u64) -> u32 {
    let hi: u32 = (v >> 32) as u32;
    if hi != 0 {
        log2_u32(hi) + 32
    } else {
        log2_u32(v as u32)
    }
}

#[inline(always)]
fn log2_u32(mut v: u32) -> u32 {
    if v == 0 {
        return 0;
    }
    let mut r: u32 = ((v > 0xFFFF) as u32) << 4;
    v >>= r;

    let mut shift = ((v > 0xFF) as u32) << 3;
    v >>= shift;
    r |= shift;

    shift = ((v > 0xF) as u32) << 2;
    v >>= shift;
    r |= shift;

    shift = ((v > 0x3) as u32) << 1;
    v >>= shift;
    r |= shift;

    r | (v >> 1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
