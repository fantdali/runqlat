#[rustfmt::skip]
use log::debug;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Initialize the eBPF profiler
    let mut profiler = runqlat::Profiler::try_new()?;

    // Need additional logic here to populate PID map in eBPF program.
    // For example, track all processes of certain containers or users.
    profiler.insert_pids(&[std::process::id()])?;

    // Periodically read histograms from eBPF maps.
    // Use these histograms as needed, e.g. export as metrics.
    let _histograms = profiler.drain_histograms();

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
