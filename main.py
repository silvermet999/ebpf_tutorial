from bcc import BPF

"""bcc dir"""
# strace -e bpf, ioctl, perf_event_open bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'
# strace look at system calls as invoked
# -e bpf...: interested in bpf system calls...
# bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }': syscall count per program
# => BPF_PROG_LOAD
# => BPF_MAP_CREATE
# => PERF_TYPE_TRACE_POINT event: associate a program with an event + an ID number
# => program loaded with ID number
# => PERF_EVENT_IOC_SET_BPF: associate tracepoint event to loaded program
# https://www.linode.com/docs/guides/how-to-install-bcc/
# cd ~/PycharmProjects/ebpf_tutorial/bcc
# mkdir build
# cd build
# sudo apt install -y clang llvm-dev libclang-dev libllvm-dev
# ls -l /usr/lib/llvm-*/lib/libclang.so
# sudo apt install linux-headers-$(uname -r)
# sudo apt install libpolly-14-dev
# sudo apt install zip
# cmake .. \
#   -DLLVM_CONFIG_EXECUTABLE=/usr/lib/llvm-14/bin/llvm-config \
#   -DClang_INCLUDE_DIR=/usr/lib/llvm-14/include \
#   -DClang_LIBRARY=/usr/lib/llvm-14/lib/libclang.so \
#   -DCMAKE_EXE_LINKER_FLAGS="-ltinfo"
# make -j$(nproc)
# sudo make install

"""linux dir"""
# sudo apt update
# sudo apt install linux-headers-$(uname -r)
# sudo apt install binutils-dev
# sudo apt install git make clang llvm libelf-dev libbfd-dev libcap-dev libzstd-dev binutils-dev libbpf-dev
# git clone --depth 1 --branch v6.1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
# cd linux/tools/bpf/bpftool
# make
# sudo make install
# sudo bpftool feature probe


"""install on debian"""
# sudo apt install bcc
# deactivate
# sudo python3 main.py


# compilation
# get user id (in the bottom 4 bytes)
program = """
int hello_world(void *ctx) {
    u64 uid;
    
    uid =bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_trace_printk("id: %d\\n", uid);
    return 0;
}
"""

b = BPF(text=program)
# attach program to event
# trigger program each time a new program is created: clone
# k is triggered on the entry to a function in the kernel
# what is the kernel function that gets invoked when clone a new process
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")
# trace what the kernel writes in program variable
b.trace_print()
