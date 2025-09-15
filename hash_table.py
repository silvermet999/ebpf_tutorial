from bcc import BPF
from time import sleep

# run multiple bpf program using a map; example hash table
# hash table has key-value pairs: key (id) and value (counter)
# p is a pointer
# if p=0 then there's no entry yet for the user id


program = """
BPF_HASH(clones); /* define hash table */

int hello_world(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;
    
    /* helper function to obtain user ID that triggered the kprobe event. 
    User ID is in the lowest 32 bits (the top 32 bits is the group ID) */
    uid =bpf_get_current_uid_gid() & 0xFFFFFFFF; 
    p = clones.lookup(&uid); /* lookup a key matching the user ID */
    /* if there's an entry, set the counter to the curr val in the hash table. 0 otherwise for both */
    if (p!=0) {
        counter = *p;
    }
    counter++;
    /* update the hash table to the new counter val */
    clones.update(&uid, &counter);

    return 0;
}

int count_openat(void *ctx) {
    hello_world;
    return 0;
}
"""

b = BPF(text=program)
clone = b.get_syscall_fnname("clone")
b.attach_kprobe(event=clone, fn_name="hello_world")
b.attach_kprobe(event="__x64_sys_openat", fn_name="count_openat")

while True:
    # loop every 2 secs to print the current state of the hash table
    sleep(2)
    s = ""
    if len(b["clones"].items()):
        # BCC auto create an object to represent the hash table
        for k,v in b["clones"].items():
            s+="ID {}: {}\t".format(k.value, v.value)
        print(s)
    else:
        print("no entry yet")

