use std::env;
use std::env::consts::ARCH;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/profile.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("profile.skel.rs");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args(format!(
            "-I{}",
            Path::new("../../../vmlinux")
                .join(match ARCH {
                    "aarch64" => "arm64",
                    "loongarch64" => "loongarch",
                    "powerpc64" => "powerpc",
                    "riscv64" => "riscv",
                    "x86_64" => "x86",
                    _ => ARCH,
                })
                .display()
        ))
        .build_and_generate(out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
