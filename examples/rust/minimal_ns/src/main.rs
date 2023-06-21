use anyhow::{bail, Result};
use nix::fcntl::{openat, OFlag};
use nix::libc::AT_FDCWD;
use nix::sys::stat::fstatat;
use nix::unistd::Pid;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

#[path = "bpf/.output/minimal_ns.skel.rs"]
mod minimal_ns;

use minimal_ns::*;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn main() -> Result<()> {
    bump_memlock_rlimit()?;

    let file_fd = openat(
        AT_FDCWD,
        Path::new("/proc/self/ns/"),
        OFlag::empty(),
        nix::sys::stat::Mode::empty(),
    )?;
    let stat_result = fstatat(file_fd, "pid", nix::fcntl::AtFlags::empty())?;

    let skel_builder = MinimalNsSkelBuilder::default();

    let mut open_skel = skel_builder.open()?;
    open_skel.bss().dev = stat_result.st_dev;
    open_skel.bss().ino = stat_result.st_ino;
    open_skel.bss().my_pid = Pid::this().as_raw() as u32;

    let mut skel = open_skel.load()?;

    skel.attach()?;

    println!("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}
