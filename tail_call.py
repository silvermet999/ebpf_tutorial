from bcc import BPF
import ctypes as ct

program = r"""
/* define maps of type prog arr, call syscall map and allow 300 entries */
BPF_PROG_ARRAY(syscall, 300);

/* attach program to sys_enter raw tracepoint which gets hit whenever any syscall is made */
int hello(struct bpf_raw_tracepoint_args *ctx) {
    /* raw tracepoint arg include the opcode indentifying which syscall in case of sys_enter */
    int opcode = ctx->args[1];
    /* make a tailcall to the entry in the prog arr whose key matches the opcode
    will be rewritten by BCC to call bpf_tail_call() before passing to the compiler */
    syscall.call(ctx, opcode);
    /* if tail call succeeds,, the line tracing out the opcode val will never be hit */
    bpf_trace_printk("another syscall: %d", opcode);
    return 0;
}

/* prog that will be loaded into the syscall prog arr map to be exec as a tail call when the opcode indicates it's an execve() syscall
gen a line of trace to indicate a new prog is being exec */
int hello_execve(void *ctx) {
    bpf_trace_printk("exec a prog");
    return 0;
}

/* loaded into the syscall prog arr */
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    if (ctx->args[1]==222) {
        bpf_trace_printk("creating a timer");
    }
    else if (ctx->args[1] == 226) {
        bpf_trace_printk("deleting a timer");
    }
    else {
        bpf_trace_printk("other op");
    }
    return 0;
}

/* no traces to be gen */
int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)
# instead of attaching to kprobe, attach to sys_enter tracepoint
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# return a file descriptor for each tail call prog
# same prog type as their parent (raw tracepoint)
# each taill call is a prog in its own
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_execve", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

# the userspace code creates entries in the syscall map
# map doesnt have to be populated for every opcode
# hello_timer() tail call exec for any set of timer related syscalls
prog_array = b.get_table("syscall")
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# ignore for syscalls that run frequently
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)

b.trace_print()