use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

use anyhow::{bail, Result};
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::SkelBuilder as _;
use structopt::StructOpt;

mod xdppass {
    include!(concat!(env!("OUT_DIR"), "/xdppass.skel.rs"));
}
use xdppass::*;

#[derive(Debug, StructOpt)]
struct Command {
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

    let skel_builder = XdppassSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    let link = skel.progs.xdp_pass.attach_xdp(opts.ifindex)?;
    skel.links = XdppassLinks {
        xdp_pass: Some(link),
    };

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
