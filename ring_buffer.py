from bcc import BPF

program = r"""
/* define macro for creating a map used to pass messages from kernel to userspace
map is called output */
BPF_PERF_OUTPUT(output);

/* everytime hello() is run, the code will write a struct's worth of data */
struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[15];
};

int hello(void *ctx) {
    /* data hold struct to be submitted and message hold the hello world str */
    struct data_t data = {};
    char message[15] = "hello everyone";
    
    /* get ID of the process that triggered the program, ID is in the top 32 bits */
    data.pid = bpf_get_current_pid_tgid() >> 32;
    /* obtain user ID */
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    /* get name of the command that's running the process that made the execve syscall
    it's a str unlike process and userID
    &data.command the address of the field where the str should be written */
    bpf_get_current_comm(&data.command, sizeof(data.command));
    /* copy message into the right place in struct everytime the message is exec */
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    /* put data into map */
    output.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# compile C code, load it into the kernel and attach it to the syscall event
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")

# callback function that will output a line of data to the screen
def print_event(cpu, data, size):
    # refer to map and grab data
    data = b["output"].event(data)
    if data.pid % 2 == 0:
        print("even " + f"{data.pid} {data.uid} {data.command.decode()} " + f"{data.message.decode()}")
    else:
        print("odd " + f"{data.pid} {data.uid} {data.command.decode()} " + f"{data.message.decode()}")


# open perf ring buffer
# print_event define that this is a callback function to be used whenever there is data to read from the buffer
b["output"].open_perf_buffer(print_event)
# poll the perf ring buffer
while True:
    b.perf_buffer_poll()