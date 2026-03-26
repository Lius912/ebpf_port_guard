#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int my_pow(int num, int power) {

	if (power == 0) {
		return 1;
	}

	for (int i = 1; i < power; i++) {
		num *= num;
	}
	return num;
}

void ip_conversion(unsigned int ip, char* buf) {
	unsigned short group1 = ip & 0x000000FF;
	unsigned short group2 = (ip & 0x0000FF00) >> 8;
	unsigned short group3 = (ip & 0x00FF0000) >> 16;
	unsigned short group4 = (ip & 0xFF000000) >> 24;
	//bpf_printk("gr1: %u", group1);
	//bpf_printk("gr2: %u", group2);
	//bpf_printk("gr3: %u", group3);
	//bpf_printk("gr4: %u", group4);
	
	//char res[15];
	unsigned short groups[4] = {group1, group2, group3, group4};
	for (int i = 0; i < 15; i++) {
	
		if (i % 4 == 3) {
			buf[i] = '.';
			continue;
		}
		int j = i / 4;
		int k = 2 - (i % 4);
		short group = groups[j];
		buf[i] = (char) ('0' + ((group / (unsigned int) my_pow(10, k)) % 10));
	}
	//buf[0] = '0' + group1 / 100;
	//buf[1] = '0' + group1 / 10 % 10;
	//buf[2] = '0' + group1 / 1 % 10;
 	buf[15] = '\0';
}

struct my_eth2_t {
	char dst[6];
	char src[6];
	short ether_type;
};

struct my_ip_t {
	char version_and_length;
	char type_of_service;
	short total_length;
	short identification;
	short flags_and_offset;
	char time_to_live;
	unsigned char protocol;
	short header_checksum;
	unsigned int src;
	unsigned int dst;
	//long long type_of_service;
};

struct my_tcp_t {
	unsigned short src_port;
	unsigned short dst_port;
};



SEC("xdp")
int hello(struct xdp_md *ctx) {

	unsigned int *data_start = ctx->data;
	unsigned int *data_end = ctx->data_end;

	//bpf_printk("Hello world!, %u", ctx->data);
	//bpf_printk("Hello world2, %u", ctx->data_end);

	unsigned int *pointer = (unsigned int*) ctx->data;
	char *one_byte_pointer = (char *) ctx->data;
	//unsigned int size = (ctx->data_end - ctx->data) / 4;

	if (pointer + sizeof(pointer[0])*14 > ctx->data_end) {
		return XDP_PASS;
	}

	struct my_eth2_t *my_eth2 = pointer;

	if (my_eth2->ether_type != 8) {
		bpf_printk("Not ipv4");
		return XDP_PASS;
	}

	//bpf_printk("llook: %u", pointer[0]);
	//bpf_printk("look2: %u", data_start[1]);

	//unsigned int start = sizeof(pointer[0]) * (size-1);

	//for (int i = 0; i <= 5; i++) {
	//	bpf_printk("look: %u", pointer[i]);
	//}

	if (one_byte_pointer + 14 + 20 > ctx->data_end) {
		bpf_printk("Too short");
		return XDP_PASS;
	}

	struct my_ip_t *my_ip = one_byte_pointer + 14;

	bpf_printk("version and len: %u", my_ip->version_and_length);
	bpf_printk("ip version: %u", my_ip->version_and_length >> 4);
	bpf_printk("ip len: %u bytes", (my_ip->version_and_length & 0b00001111) * 4);

	bpf_printk("protocol: %u", my_ip->protocol);
	bpf_printk("src: %u", my_ip->src);
	bpf_printk("dst: %u", my_ip->dst);
	

	char buf[16];
	ip_conversion(my_ip->src, &buf);
	bpf_printk("src: %s", buf);
	ip_conversion(my_ip->dst, &buf);
	bpf_printk("dst: %s", buf);

	if (my_ip + sizeof(struct my_ip_t) + sizeof(struct my_tcp_t) > ctx->data_end) {
		bpf_printk("Too short for TCP header");
		return XDP_PASS;
	}

	//bpf_printk("my_ip: %u", my_ip);
	//bpf_printk("size of my_ip: %u", sizeof(struct my_ip_t));

	//struct my_tcp_t *my_tcp = my_ip + sizeof(struct my_ip_t);
	//bpf_printk("mytcp: %u", my_tcp);

	//bpf_printk("src port1: %u", my_tcp->src_port);
	//bpf_printk("dst port1: %u", my_tcp->dst_port);

	struct my_tcp_t *my_tcp2 = (char *)my_ip + sizeof(struct my_ip_t);
	//bpf_printk("mtcp2: %u", my_tcp2);
	bpf_printk("src port2: %u", my_tcp2->src_port);
	bpf_printk("dst port2: %u", my_tcp2->dst_port);

	bpf_printk("src port3: %u", (unsigned short) ((my_tcp2->src_port & 0x00FF) << 8) + ((my_tcp2->src_port & 0xFF00) >> 8));
	bpf_printk("dst port3: %u", (unsigned short) ((my_tcp2->dst_port & 0x00FF) << 8) + ((my_tcp2->dst_port & 0xFF00) >> 8));

	//bpf_printk("length:  %u", my->version & 0b00001111);
	//bpf_printk("type_of: %u", my->type_of_service);

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
