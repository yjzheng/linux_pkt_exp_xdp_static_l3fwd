#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <poll.h>	
#include <arpa/inet.h>	
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/socket.h>	
#include <sys/mman.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "libbpf_helpers.h"



#define __bpf_percpu_val_align  __attribute__((__aligned__(8)))

#define BPF_DECLARE_PERCPU(type, name, nr_cpus)                          \
        struct { type v; /* padding */ } __bpf_percpu_val_align \
                name[nr_cpus]
#define BPF_PERCPU(name, cpu) name[(cpu)].v

struct flowv4_keys { //need to sync with ebpf program
    __be32 dst;
};

struct pair {
    uint64_t packets;
    uint64_t bytes;
};



void dump_hex(unsigned int len, unsigned char* data){
	unsigned int idx;
	printf("len:%d, data =%p\n",len,data);		
	for (idx=0; idx<len && idx<1000;idx++){
		printf("%s",(idx%32==0)?"\n":(idx%8==0)?" ":(idx%4==0)?"-":"");
		printf("%02x",data[idx]);		
	}	
}
int handle_frame(struct tpacket_hdr* thdr, struct sockaddr_ll* saddr, char* l2, char* l3){
	//printf("dummy print code\n");
	//printf("dummy print code 2\n");
	//dump_hex(thdr->tp_len,l2);
	//printf("\nget frame! l2=%p,l3=%p,thdr=%p, saddr=%p ,data:\n",l2,l3,thdr,saddr);
	return 0;
}

int main(){
	//create socket 
	int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1) {
		perror("socket");
		exit(1);
	}

	//allocate ring buffer 
	struct tpacket_req req = {0};
	int snaplen=1500;
	req.tp_frame_size = TPACKET_ALIGN(TPACKET_HDRLEN + ETH_HLEN) + TPACKET_ALIGN(snaplen);
	req.tp_block_size = sysconf(_SC_PAGESIZE);
	while (req.tp_block_size < req.tp_frame_size) {
		req.tp_block_size <<= 1;
	}
	req.tp_block_nr = sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) / (2 * req.tp_block_size);
	size_t frames_per_buffer = req.tp_block_size / req.tp_frame_size;
	req.tp_frame_nr = req.tp_block_nr * frames_per_buffer;
	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req))==-1) {
		perror("setsockopt");
		exit(1);
	}

	//map to user space buffer
	size_t rx_ring_size = req.tp_block_nr * req.tp_block_size;
	char* rx_ring = mmap(0, rx_ring_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

	struct pollfd fds[1] = {0};
	fds[0].fd = fd;
	fds[0].events = POLLIN;
	size_t frame_idx = 0;
	char* frame_ptr = rx_ring;
	
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_SOCKET_FILTER,
	};
	const char *objfile = "af_packet_filter.o";
	const char *prog_name = "socket_afp";
	bool filename_set = false;
	struct bpf_program *prog;
	int prog_fd, map_fd = -1;
	struct bpf_object *obj;
	
	if (load_obj_file(&prog_load_attr, &obj, objfile, filename_set))
		return 1;
	prog = bpf_object__find_program_by_title(obj, prog_name);
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		printf("program not found: %s\n", strerror(prog_fd));
		return 1;
	}
	map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
						"flow_table_v4"));
	if (map_fd < 0) {
		printf("map not found: %s\n", strerror(map_fd));
		return 1;
	}		
    int nr_cpus=1;//temperary assign
    //ref: AFPInsertHalfFlow insert 192.168.0.129, 192.168.1.128 into bypass dip list   
    BPF_DECLARE_PERCPU(struct pair, value, nr_cpus);
    unsigned int i;
    /* We use a per CPU structure so we have to set an array of values as the kernel
     * is not duplicating the data on each CPU by itself. */
    for (i = 0; i < nr_cpus; i++) {
        BPF_PERCPU(value, i).packets = 0;
        BPF_PERCPU(value, i).bytes = 0;
    }

    //set bypass flow
#define ENS38_DIP_N   0x8100a8c0                    //192.168.0.129 
#define ENS39_DIP_N   0x8001a8c0  //192.168.1.128

#define ENS38_DIP   0xc0a80081                    //192.168.0.129
#define ENS39_DIP   0xc0a80180   //192.168.1.128

    struct flowv4_keys keys ;
    keys.dst = ENS38_DIP;

    if (bpf_map_update_elem(map_fd, (void*)&keys, value, BPF_NOEXIST) != 0){
		printf("map update fail ENS38_DIP_N\n");
		return 1;
    }
    keys.dst = ENS39_DIP;
    if (bpf_map_update_elem(map_fd, (void*)&keys, value, BPF_NOEXIST) != 0){
		printf("map update fail for ENS39_DIP_N\n");
		return 1;
    }
    
    //attach
    if ((prog_fd<0) || setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        printf("SO_ATTACH_BPF error");
		exit(1);
    }    	
	

	while (1) {
		struct tpacket_hdr* tphdr = (struct tpacket_hdr*)frame_ptr;
		while (!(tphdr->tp_status & TP_STATUS_USER)) {
			if (poll(fds, 1, -1) == -1) {
				perror("poll");
				exit(1);
			}
		}

		struct sockaddr_ll* addr = (struct sockaddr_ll*)(frame_ptr + TPACKET_HDRLEN - sizeof(struct sockaddr_ll));
		char* l2content = frame_ptr + tphdr->tp_mac;
		char* l3content = frame_ptr + tphdr->tp_net;
		handle_frame(tphdr, addr, l2content, l3content);

		frame_idx = (frame_idx + 1) % req.tp_frame_nr;
		int buffer_idx = frame_idx / frames_per_buffer;
		char* buffer_ptr = rx_ring + buffer_idx * req.tp_block_size;
		int frame_idx_diff = frame_idx % frames_per_buffer;
		frame_ptr = buffer_ptr + frame_idx_diff * req.tp_frame_size;
	}
	return 0;
}

