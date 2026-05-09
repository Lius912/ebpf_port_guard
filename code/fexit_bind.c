#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define pid_t __u32
#define prog_id_t __u16
#define port_t __u16
#define smallest_num_t __u8

struct prog_id_port_t {
  prog_id_t prog_id;
  port_t port;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct prog_id_port_t);
    __type(value, smallest_num_t);
    __uint(max_entries, 4096);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} prog_id_ports_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, port_t);
    __type(value, prog_id_t);
    __uint(max_entries, 4096);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} local_port_prog_id_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, prog_id_t);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} progname_prog_id_map SEC(".maps");

SEC("fexit/__sys_bind")
//int BPF_PROG(my_try, int fd, struct sock_addr *uservaddr, int addrlen, int ret) {
int BPF_PROG(my_try_bind, int fd, struct sockaddr *umyaddr, int addrlen, int ret) {

    bpf_printk("[bind] fd: %u", fd);
    //bpf_printk("[bind] ret: %u", ret);
    bpf_printk("[bind] len: %u", addrlen);

    struct sockaddr myaddr;
    bpf_probe_read(&myaddr, 16, umyaddr);

    bpf_printk("[bind]  myaddr: %u", &myaddr);

    //char* myaddr_new = (char*) &myaddr;
    //bpf_printk("[bind] k: %u%u%u", *((unsigned short*)myaddr_new), *((unsigned short*)(myaddr_new+2)), *((unsigned int*)(myaddr_new+4)));

    unsigned short family = myaddr.sa_family;
    bpf_printk("[bind] family: %u", family);
    bpf_printk("[bind] family: %u", (&myaddr)->sa_family);

    unsigned short sin_port = ((struct sockaddr_in *) &myaddr)->sin_port;
    sin_port = (sin_port << 8) + (sin_port >> 8);
    bpf_printk("[bind] port: %u", sin_port);

    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid & 0xFFFFFFFF;
    uint32_t tgid = pid_tgid >> 32;

    bpf_printk("[bind] pid: %u, tgid: %u", pid, tgid);

    char prog_name[TASK_COMM_LEN];
    if (bpf_get_current_comm(prog_name, TASK_COMM_LEN)) {
        bpf_printk("Failed to get comm\n");
        return 0;
    }
    
    bpf_printk("Hello from %s\n", prog_name);
    prog_id_t *prog_id_search = bpf_map_lookup_elem(&progname_prog_id_map, prog_name);
    if (!prog_id_search) {
        bpf_printk("prog not in map");
    } else {
        prog_id_t prog_id = *prog_id_search;
        
        struct prog_id_port_t prog_id_port = {prog_id, sin_port};
       	smallest_num_t *prog_id_port_search = bpf_map_lookup_elem(&prog_id_ports_map, &prog_id_port);
       	
       	if (!prog_id_port_search) {
       		bpf_printk("prog in map, port - not");
       		return 0;
       	}
        
        bpf_map_update_elem(&local_port_prog_id_map, &sin_port, &prog_id, BPF_ANY);
        bpf_printk("prog in map");
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
