add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

add_requires("linux-tools", {configs = {bpftool = true}})
add_requires("libbpf", {system = false})
if is_plat("android") then
    add_requires("ndk >=22.x", "argp-standalone")
    set_toolchains("@ndk", {sdkver = "23"})
else
    add_requires("llvm >=10.x")
    set_toolchains("@llvm")
    add_requires("linux-headers")
end

add_includedirs("../../vmlinux")
add_packages("linux-tools", "linux-headers", "libbpf")

target("minimal")
    set_kind("binary")
    add_files("minimal*.c")

target("bootstrap")
    set_kind("binary")
    add_files("bootstrap*.c")
    if is_plat("android") then
        add_packages("argp-standalone")
    end

target("fentry")
    set_kind("binary")
    add_files("fentry*.c")

target("kprobe")
    set_kind("binary")
    add_files("kprobe*.c")
    if is_plat("android") then
        -- TODO we need fix vmlinux.h tu support android
        set_default(false)
    end
