#include "read_data.h"
#include "./include/skel.h"
#pragma once
#include <stdio.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <algorithm>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <stdint.h>


class arp_table_entry {
public:
    uint32_t ip;
	uint8_t mac[6];

    arp_table_entry() {}

    ~arp_table_entry() {}
};

// Binary Search function
int binary_search_rtable (uint32_t destination_ip, std::vector<route_table_entry> &rtable, int r, int l, int m) {

    while (l <= r) { 
        int m = l + (r - l) / 2; 

		int match = 0;
		uint32_t matching_prefix = 0;

		if (rtable[m].prefix == (rtable[m].mask & destination_ip)) {
			while (rtable[m].prefix == (rtable[m].mask & destination_ip)) {
				m--;
			}
			return m + 1;
		}

        if (rtable[m].prefix <= (rtable[m].mask & destination_ip)) { 
            r = m - 1; 
		} else {
            l = m + 1; 
		}

    }  
	
	return -1;
}

// Best Route function
route_table_entry *get_best_route (uint32_t destination_ip, std::vector<route_table_entry> &rtable) {
	int max_bits = 0;
	int pos = -1;

	pos = binary_search_rtable(destination_ip, rtable, rtable.size() - 1, 0, 0);
	
	if (pos != -1) {
		return &rtable[pos];
	}

	return nullptr;
}

// Sort 
bool ip_is_greater (route_table_entry e1, route_table_entry e2) {
	if (e1.prefix > e2.prefix) {
		return true;
	} else if (e1.prefix == e2.prefix) {
		if (e1.mask > e2.mask) {
			return true;
		}
	}
	return false;
}

// Checksum function
uint16_t ip_checksum(void* vdata,size_t length) {
	char* data = (char*)vdata;

	uint64_t acc = 0xffff;
	unsigned int offset = ((uintptr_t)data)&3;

	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	char* data_end = data + (length&~3);
	while (data != data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc += ntohl(word);
		data += 4;
	}
	length &= 3;

	if (length) {
		uint32_t word = 0;
		memcpy(&word,data,length);
		acc += ntohl(word);
	}

	acc = (acc&0xffffffff) + (acc>>32);
	while (acc >> 16) {
		acc = (acc&0xffff) + (acc>>16);
	}

	if (offset&1) {
		acc = ((acc&0xff00) >> 8) | ((acc&0x00ff) << 8);
	}

	return htons(~acc);
}

// ARP entry function
arp_table_entry *get_arp_entry(std::vector<arp_table_entry> &arp_table, uint32_t ip_dest) {
	for (int i = 0; i < arp_table.size(); ++i) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}
	return nullptr;
}

// IP modify function
void modify_ip(void *ip1, void *ip2) {

	uint8_t dest_ip[4];
	memcpy(dest_ip, ip1, sizeof(uint8_t) * 4);
	memcpy(ip1, ip2, sizeof(uint8_t) * 4);
	memcpy(ip2, dest_ip , sizeof(uint8_t) * 4);
}

// MAC modify function
void modify_mac(uint8_t *mac1, uint8_t *mac2, uint8_t *mac3, packet m) {
				//prev dest 	// new dest    // source
	memcpy(mac1, mac2, sizeof(uint8_t) * 6);
	get_interface_mac(m.interface, mac3);
}

// Modify IP header - checksum & ttl
void change_ip_header(struct iphdr *ip_hdr, int ttl) {
	ip_hdr->ttl -= ttl;
	ip_hdr->check = 0;
	ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
}

// Change IP header  
void change_ip_header_icmp(struct iphdr *ip_hdr) {
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
}

// Change ICMP header
void change_icmp_header(struct icmphdr *icmp_hdr, int type) {
	icmp_hdr->type = type; // htons(ICMP_TIME_EXCEEDED);
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));
}

// Change ARP fields
void change_arp_inexistent_entry(struct ether_arp *arp_hdr) {
	arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	arp_hdr->ea_hdr.ar_hrd = htons(1);
	arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
	arp_hdr->ea_hdr.ar_hln = 6;
	arp_hdr->ea_hdr.ar_pln = 4;
}