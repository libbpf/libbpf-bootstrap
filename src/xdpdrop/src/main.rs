use std::{thread, time};

use anyhow::{bail, Result};
use structopt::StructOpt;

mod bpf;
use bpf::*;

#[derive(Debug, StructOpt)]
struct Command {
    /// Duration to stop this program
    #[structopt(default_value = "10000")]
    duration: u64,
    /// Interface index to attach XDP program
    #[structopt(default_value = "0")]
    ifindex: i32,
}

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
    let opts = Command::from_args();

    bump_memlock_rlimit()?;

    let skel_builder = XdpdropSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let link = skel.progs().xdp_drop().attach_xdp(opts.ifindex)?;
    skel.links = XdpdropLinks{
        xdp_drop: Some(link),
    };

    thread::sleep(time::Duration::from_millis(opts.duration));
    Ok(())
}
