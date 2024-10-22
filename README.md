# signBpf base on libbpf-bootstrap: BPF applicatin that checks signature and determine resources allowed.

## lsm
`lsm` serves as an illustrative example of utilizing [LSM BPF](https://docs.kernel.org/bpf/prog_lsm.html). In this example, the `bpf()` system call is effectively blocked. Once the `lsm` program is operational, its successful execution can be confirmed by using the `bpftool prog list` command.

```shell
$ sudo ./lsm
libbpf: loading object 'lsm_bpf' from buffer
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
..........
```

The output from `lsm` in `/sys/kernel/debug/tracing/trace_pipe` is expected to resemble the following:

````shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
         bpftool-70646   [002] ...11 279318.416393: bpf_trace_printk: LSM: block bpf() worked
         bpftool-70646   [002] ...11 279318.416532: bpf_trace_printk: LSM: block bpf() worked
         bpftool-70646   [002] ...11 279318.416533: bpf_trace_printk: LSM: block bpf() worked
````

When the `bpf()` system call gets blocked, the `bpftool prog list` command yields the following output:

```shell
$ sudo bpftool prog list
Error: can't get next program: Operation not permitted
```

# Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```

## C Examples

Makefile build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ make
$ sudo ./bootstrap
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
00:21:22 EXIT  python3.8        4032353 4032352 [0] (123ms)
00:21:22 EXEC  mkdir            4032379 4032337 /usr/bin/mkdir
00:21:22 EXIT  mkdir            4032379 4032337 [0] (1ms)
00:21:22 EXEC  basename         4032382 4032381 /usr/bin/basename
00:21:22 EXIT  basename         4032382 4032381 [0] (0ms)
00:21:22 EXEC  sh               4032381 4032380 /bin/sh
00:21:22 EXEC  dirname          4032384 4032381 /usr/bin/dirname
00:21:22 EXIT  dirname          4032384 4032381 [0] (1ms)
00:21:22 EXEC  readlink         4032387 4032386 /usr/bin/readlink
^C
```


# Troubleshooting

Libbpf debug logs are quire helpful to pinpoint the exact source of problems,
so it's usually a good idea to look at them before starting to debug or
posting question online.

`./minimal` is always running with libbpf debug logs turned on.

For `./bootstrap`, run it in verbose mode (`-v`) to see libbpf debug logs:

```shell
$ sudo ./bootstrap -v
libbpf: loading object 'bootstrap_bpf' from buffer
libbpf: elf: section(2) tp/sched/sched_process_exec, size 384, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exec': found program 'handle_exec' at insn offset 0 (0 bytes), code size 48 insns (384 bytes)
libbpf: elf: section(3) tp/sched/sched_process_exit, size 432, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exit': found program 'handle_exit' at insn offset 0 (0 bytes), code size 54 insns (432 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of bootstrap_bpf is Dual BSD/GPL
...
```
