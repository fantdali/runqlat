use anyhow::{Context, anyhow};
use aya::programs::RawTracePoint;
use log::warn;
use runqlat_common::Histogram;
use std::collections::HashMap;

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

    pub fn drain_histograms(&mut self) -> anyhow::Result<HashMap<u32, Histogram>> {
        let hist_map = self
            .ebpf
            .map_mut("HIST")
            .ok_or_else(|| anyhow!("HIST map not found"))?;

        let mut hist_map: aya::maps::HashMap<_, u32, Histogram> =
            aya::maps::HashMap::try_from(hist_map).context("invalid HIST map")?;

        let out: HashMap<u32, Histogram> = hist_map
            .iter()
            .collect::<Result<_, _>>()
            .context("failed to read HIST entries")?;

        for (pid, _) in &out {
            let _ = hist_map.remove(pid);
        }

        Ok(out)
    }

    pub fn insert_pids(&mut self, pids: &[u32]) -> anyhow::Result<()> {
        let pid_map = self
            .ebpf
            .map_mut("PID")
            .ok_or_else(|| anyhow!("PID map not found"))?;

        let mut pid_map: aya::maps::HashMap<_, u32, u8> =
            aya::maps::HashMap::try_from(pid_map).context("invalid PID map")?;

        for pid in pids {
            pid_map
                .insert(pid, 0, 0)
                .context("failed to insert pid into PID map")?;
        }

        Ok(())
    }

    pub fn remove_pids(&mut self, pids: &[u32]) -> anyhow::Result<()> {
        let pid_map = self
            .ebpf
            .map_mut("PID")
            .ok_or_else(|| anyhow!("PID map not found"))?;

        let mut pid_map: aya::maps::HashMap<_, u32, u8> =
            aya::maps::HashMap::try_from(pid_map).context("invalid PID map")?;

        for pid in pids {
            pid_map
                .remove(pid)
                .context("failed to insert pid into PID map")?;
        }

        Ok(())
    }
}
