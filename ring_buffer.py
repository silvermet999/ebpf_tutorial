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
    char message[12];
};

int hello(void *ctx) {
    /* data hold struct 
    struct data_t data = {};
    
"""
