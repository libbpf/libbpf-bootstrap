use anyhow::{bail, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{thread, time};

mod exitsnoop {
    include!(concat!(env!("OUT_DIR"), "/exitsnoop.skel.rs"));
}
use exitsnoop::*;
use libc::{c_char, c_int, c_uint, c_ulonglong};

const TASK_COMM_LEN: usize = 16;

#[repr(C)]
struct event {
    pid: c_int,
    ppid: c_int,
    exit_code: c_uint,
    duration_ns: c_ulonglong,
    comm: [c_char; TASK_COMM_LEN],
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
    let skel_builder = ExitsnoopSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    bump_memlock_rlimit()?;
    let maps = skel.maps();
    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder.add(maps.rb(), event_handler).unwrap();
    let ringbuf = builder.build().unwrap();
    while ringbuf.poll(Duration::MAX).is_ok() {}

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

fn event_handler(data: &[u8]) -> i32 {
    let event = unsafe { &*(data.as_ptr() as *const event) };
    let comm = unsafe { std::ffi::CStr::from_ptr(event.comm.as_ptr()) };
    println!(
        "pid: {}, ppid: {}, exit_code: {}, duration_ns: {}, comm: {}",
        event.pid,
        event.ppid,
        event.exit_code,
        event.duration_ns,
        comm.to_str().unwrap()
    );
    0
}
