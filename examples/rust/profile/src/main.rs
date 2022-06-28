use std::u64;

use std::boxed::Box;
use std::io::Error;
use std::mem;
use std::result::Result;
use std::time::Duration;

extern crate nix;
use nix::unistd::close;

extern crate libbpf_rs;

extern crate clap;
use clap::Parser;

#[path = "bpf/.output/profile.skel.rs"]
mod profile;
use profile::*;

extern crate blazesym;
use blazesym::*;

extern crate libc;

mod syscall;

const MAX_STACK_DEPTH: usize = 128;
const TASK_COMM_LEN: usize = 16;

// A Rust version of stacktrace_event in profile.h
#[repr(C)]
struct stacktrace_event {
    pid: u32,
    cpu_id: u32,
    comm: [u8; TASK_COMM_LEN],
    kstack_size: i32,
    ustack_size: i32,
    kstack: [u64; MAX_STACK_DEPTH],
    ustack: [u64; MAX_STACK_DEPTH],
}

fn init_perf_monitor(freq: u64) -> Vec<i32> {
    let nprocs = libbpf_rs::num_possible_cpus().unwrap();
    let pid = -1;
    let buf: Vec<u8> = vec![0; mem::size_of::<syscall::perf_event_attr>()];
    let mut attr = unsafe {
        Box::<syscall::perf_event_attr>::from_raw(
            buf.leak().as_mut_ptr() as *mut syscall::perf_event_attr
        )
    };
    attr._type = syscall::PERF_TYPE_HARDWARE;
    attr.size = mem::size_of::<syscall::perf_event_attr>() as u32;
    attr.config = syscall::PERF_COUNT_HW_CPU_CYCLES;
    attr.sample.sample_freq = freq;
    attr.flags = 1 << 10; // freq = 1
    (0..nprocs)
        .map(|cpu| {
            let fd = syscall::perf_event_open(attr.as_ref(), pid, cpu as i32, -1, 0);
            fd as i32
        })
        .collect()
}

fn attach_perf_event(
    pefds: &[i32],
    prog: &mut libbpf_rs::Program,
) -> Vec<Result<libbpf_rs::Link, libbpf_rs::Error>> {
    pefds
        .iter()
        .map(|pefd| prog.attach_perf_event(*pefd))
        .collect()
}

// Pid 0 means a kernel space stack.
fn show_stack_trace(stack: &[u64], symbolizer: &BlazeSymbolizer, pid: u32) {
    let src = if pid == 0 {
        SymbolSrcCfg::Kernel {
            kallsyms: None,
            kernel_image: None,
        }
    } else {
        SymbolSrcCfg::Process { pid: Some(pid) }
    };

    let syms = symbolizer.symbolize(&[src], stack);
    for i in 0..stack.len() {
        if syms.len() <= i || syms[i].len() == 0 {
            println!("  {} [<{:016x}>]", i, stack[i]);
            continue;
        }

        if syms[i].len() == 1 {
            let sym = &syms[i][0];
            if !sym.path.is_empty() {
                println!(
                    "  {} [<{:016x}>] {}+0x{:x} {}:{}",
                    i,
                    stack[i],
                    sym.symbol,
                    stack[i] - sym.start_address,
                    sym.path,
                    sym.line_no
                );
            } else {
                println!(
                    "  {} [<{:016x}>] {}+0x{}",
                    i,
                    stack[i],
                    sym.symbol,
                    stack[i] - sym.start_address
                );
            }
            continue;
        }

        println!("  {} [<{:016x}>]", i, stack[i]);

        for sym in &syms[i] {
            if !sym.path.is_empty() {
                println!(
                    "        {}+0x{:x} {}:{}",
                    sym.symbol,
                    stack[i] - sym.start_address,
                    sym.path,
                    sym.line_no
                );
            } else {
                println!("        {}+0x{}", sym.symbol, stack[i] - sym.start_address);
            }
        }
    }
}

fn event_handler(symbolizer: &BlazeSymbolizer, data: &[u8]) -> ::std::os::raw::c_int {
    if data.len() != mem::size_of::<stacktrace_event>() {
        eprintln!(
            "Invalid size {} != {}",
            data.len(),
            mem::size_of::<stacktrace_event>()
        );
        return 1;
    }

    let event = unsafe { &*(data.as_ptr() as *const stacktrace_event) };

    if event.kstack_size <= 0 && event.ustack_size <= 0 {
        return 1;
    }

    let comm = std::str::from_utf8(&event.comm)
        .or::<Error>(Ok("<unknown>"))
        .unwrap();
    println!("COMM: {} (pid={}) @ CPU {}", comm, event.pid, event.cpu_id);

    if event.kstack_size > 0 {
        println!("Kernel:");
        show_stack_trace(
            &event.kstack[0..(event.kstack_size as usize / mem::size_of::<u64>())],
            symbolizer,
            0,
        );
    } else {
        println!("No Kernel Stack");
    }

    if event.ustack_size > 0 {
        println!("Userspace:");
        show_stack_trace(
            &event.ustack[0..(event.ustack_size as usize / mem::size_of::<u64>())],
            symbolizer,
            event.pid,
        );
    } else {
        println!("No Userspace Stack");
    }

    println!();
    0
}

#[derive(Parser, Debug)]
struct Args {
    /// Sampling frequency
    #[clap(short, default_value_t = 1)]
    freq: u64,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let freq = if args.freq < 1 { 1 } else { args.freq };

    let symbolizer = BlazeSymbolizer::new()?;

    let skel_builder = ProfileSkelBuilder::default();
    let open_skel = skel_builder.open().unwrap();
    let mut skel = open_skel.load().unwrap();

    let pefds = init_perf_monitor(freq);
    let _links = attach_perf_event(&pefds, skel.progs_mut().profile());

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        .add(skel.maps().events(), move |data| {
            event_handler(&symbolizer, data)
        })
        .unwrap();
    let ringbuf = builder.build().unwrap();
    while ringbuf.poll(Duration::MAX).is_ok() {}

    for pefd in pefds {
        close(pefd)?;
    }

    Ok(())
}
