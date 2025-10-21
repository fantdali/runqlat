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
    EbpfContext,
    helpers::bpf_ktime_get_ns,
    macros::{btf_tracepoint, map},
    maps::HashMap,
    programs::BtfTracePointContext,
};
use vmlinux::task_struct;

const MAX_ENTRIES: u32 = 2048;
const MAX_SLOTS: usize = 26;
const TASK_RUNNING: u32 = 0;

pub type Hist = [u32; MAX_SLOTS];

#[map(name = "PIDS")]
static mut PIDS: HashMap<u32, u8> = HashMap::<u32, u8>::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "START")]
static mut START: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(MAX_ENTRIES, 0);

#[map(name = "HISTS")]
static mut HISTS: HashMap<u32, Hist> = HashMap::<u32, Hist>::with_max_entries(MAX_ENTRIES, 0);

#[btf_tracepoint(function = "sched_wakeup")]
pub fn sched_wakeup(_ctx: BtfTracePointContext) -> i32 {
    // let tgid = ...
    // if unsafe { PIDS.get(&tgid).is_none() } {
    //     return 0;
    // }
    // save_start_ts(ctx.pid());
    0
}

#[btf_tracepoint(function = "sched_wakeup_new")]
pub fn sched_wakeup_new(_ctx: BtfTracePointContext) -> i32 {
    // let tgid = ...
    // if unsafe { PIDS.get(&tgid).is_none() } {
    //     return 0;
    // }
    // save_start_ts(ctx.pid());
    0
}

// https://github.com/torvalds/linux/blob/6548d364a3e850326831799d7e3ea2d7bb97ba08/include/trace/events/sched.h#L220-L267
#[btf_tracepoint(function = "sched_switch")]
pub fn sched_switch(ctx: BtfTracePointContext) -> i32 {
    let prev: *const task_struct = unsafe { ctx.arg(1) };
    let next: *const task_struct = unsafe { ctx.arg(2) };
    if prev.is_null() || next.is_null() {
        return 0;
    }
    // let prev = unsafe { &*prev };
    // let next = unsafe { &*next };

    let prev_pid = unsafe { (*prev).pid };
    aya_log_ebpf::info!(&ctx, "sched_switch: prev={} next=", prev_pid);

    // aya_log_ebpf::info!(
    //     &ctx,
    //     "sched_switch: prev pid={} tgid={} state={} -> next pid={} tgid={}",
    //     prev.pid,
    //     prev.tgid,
    //     prev.__state,
    //     next.pid,
    //     next.tgid
    // );

    0
}

// task_struct https://marselester.com/linux-process.html
#[inline(always)]
#[allow(dead_code)]
fn try_sched_switch(ctx: BtfTracePointContext) {
    let prev: *const task_struct = unsafe { ctx.arg(1) };
    let next: *const task_struct = unsafe { ctx.arg(2) };
    if prev.is_null() || next.is_null() {
        return;
    }
    let prev = unsafe { &*prev };
    let next = unsafe { &*next };

    // if prev running and prev.tgid tracked, save start ts of prev.pid
    let prev_tgid = prev.tgid as u32;
    if prev.__state == TASK_RUNNING && unsafe { PIDS.get(&prev_tgid).is_some() } {
        save_start_ts(prev.pid as u32);
    }

    // if next.tgid not tracked, return
    let next_tgid = next.tgid as u32;
    if unsafe { PIDS.get(&next_tgid).is_none() } {
        return;
    }

    let next_pid = next.pid as u32;

    // get start ts of next.pid
    // if not found, return
    let start_ts = match unsafe { START.get(&next_pid) } {
        Some(ts) => *ts,
        None => return,
    };

    let now_ts = unsafe { bpf_ktime_get_ns() } as u64;
    if now_ts < start_ts {
        let _ = unsafe { START.remove(&next_pid) };
        return;
    }
    let delta_us = (now_ts - start_ts) / 1000;

    let mut slot = log2_u64(delta_us) as usize;
    if slot >= MAX_SLOTS {
        slot = MAX_SLOTS - 1;
    }

    // inc hist slot of next.tgid
    let next_tgid = next.tgid as u32;
    if let Some(hist) = unsafe { HISTS.get_ptr_mut(&next_tgid) } {
        unsafe {
            (*hist)[slot] = (*hist)[slot].saturating_add(1);
        }
    } else {
        let mut hist = [0; MAX_SLOTS];
        hist[slot] = 1;
        let _ = unsafe { HISTS.insert(&next_tgid, &hist, 0) };
    }

    let _ = unsafe { START.remove(&next_pid) };
}

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
