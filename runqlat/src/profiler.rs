use std::collections::HashMap;

use anyhow::{Context, anyhow};
use aya::programs::RawTracePoint;
use log::warn;
use runqlat_common::Histogram;

pub struct Profiler {
    pub ebpf: aya::Ebpf,
}

impl Profiler {
    pub fn try_new() -> anyhow::Result<Self> {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/runqlat"
        )))?;
        match aya_log::EbpfLogger::init(&mut ebpf) {
            Err(e) => {
                // This can happen if you remove all log statements from your eBPF program.
                warn!("failed to initialize eBPF logger: {e}");
            }
            Ok(logger) => {
                let mut logger =
                    tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
                tokio::task::spawn(async move {
                    loop {
                        let mut guard = logger.readable_mut().await.unwrap();
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
        }

        for tp in ["sched_wakeup", "sched_wakeup_new", "sched_switch"] {
            let prog: &mut RawTracePoint = ebpf.program_mut(tp).unwrap().try_into()?;
            prog.load()?;
            prog.attach(tp)?;
        }

        Ok(Self { ebpf })
    }

    pub fn histograms(&mut self) -> anyhow::Result<HashMap<u32, Histogram>> {
        let map = self
            .ebpf
            .map_mut("HIST")
            .ok_or_else(|| anyhow!("HIST map not found"))?;

        let mut hist: aya::maps::HashMap<_, u32, Histogram> =
            aya::maps::HashMap::try_from(map).context("invalid HIST map")?;

        let out: HashMap<u32, Histogram> = hist
            .iter()
            .collect::<Result<_, _>>()
            .context("failed to read HIST entries")?;

        for (pid, _) in &out {
            let _ = hist.remove(pid);
        }

        Ok(out)
    }
}
