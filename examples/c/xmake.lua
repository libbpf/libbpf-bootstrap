add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

add_requires("libelf", "zlib")
add_requires("linux-tools", {configs = {bpftool = true}})
if is_plat("android") then
    add_requires("ndk >=22.x", "argp-standalone")
    set_toolchains("@ndk", {sdkver = "23"})
else
    add_requires("llvm >=10.x")
    set_toolchains("@llvm")
    add_requires("linux-headers")
end

add_includedirs("../../vmlinux")

target("libbpf")
    set_kind("static")
    set_basename("bpf")
    add_files("../../libbpf/src/*.c")
    add_includedirs("../../libbpf/include")
    add_includedirs("../../libbpf/include/uapi", {public = true})
    add_includedirs("$(buildir)", {interface = true})
    add_configfiles("../../libbpf/src/(*.h)", {prefixdir = "bpf"})
    add_packages("libelf", "zlib")
    if is_plat("android") then
        add_defines("__user=", "__force=", "__poll_t=uint32_t")
    end

target("minimal")
    set_kind("binary")
    add_deps("libbpf")
    add_files("minimal*.c")
    add_packages("linux-tools", "linux-headers")

target("bootstrap")
    set_kind("binary")
    add_deps("libbpf")
    add_files("bootstrap*.c")
    add_packages("linux-tools", "linux-headers")
    if is_plat("android") then
        add_packages("argp-standalone")
    end

target("fentry")
    set_kind("binary")
    add_deps("libbpf")
    add_files("fentry*.c")
    add_packages("linux-tools", "linux-headers")

target("kprobe")
    set_kind("binary")
    add_deps("libbpf")
    add_files("kprobe*.c")
    add_packages("linux-tools", "linux-headers")
    if is_plat("android") then
        -- TODO we need fix vmlinux.h tu support android
        set_default(false)
    end
