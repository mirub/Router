#include "read_data.h"
#include "arp_table.h"
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <stdint.h>
#include "./include/skel.h"
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

route_table_entry *get_best_route (uint32_t destination_ip, std::vector<route_table_entry> &rtable) {
	int max_bits = 0;
	int pos = -1;

	pos = binary_search_rtable(destination_ip, rtable, rtable.size() - 1, 0, 0);
	
	if (pos != -1) {
		return &rtable[pos];
	}

	return nullptr;
}

route_table_entry *get_best_route_1 (uint32_t destination_ip, std::vector<route_table_entry> &rtable) {
	int max_bits = 0;
	int pos = -1;

	for (int i = 0; i < rtable.size(); ++i) {
		if (__builtin_popcount(rtable[i].mask) > max_bits && 
			(rtable[i].prefix == (destination_ip & rtable[i].mask))) {
			max_bits = __builtin_popcount(rtable[i].mask);
			pos = i;
		}
	}
	
	if (pos != -1) {
		return &rtable[pos];
	}

	return nullptr;
}

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

bool is_gr (int a, int b) {
	if (a > b) {
		return true;
	}
	return false;
}


uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

arp_table_entry *get_arp_entry(std::vector<arp_table_entry> &arp_table, uint32_t ip_dest) {
	for (int i = 0; i < arp_table.size(); ++i) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}
	return nullptr;
}

void modify_ip(uint8_t *ip1, uint8_t *ip2) {

	uint8_t dest_ip[4];
	memcpy(dest_ip, ip1, sizeof(uint8_t) * 4);
	memcpy(ip1, ip2, sizeof(uint8_t) * 4);
	memcpy(ip2, dest_ip , sizeof(uint8_t) * 4);
}

void modify_mac(uint8_t *mac1, uint8_t *mac2, uint8_t *mac3, packet m) {
				//prev dest 	// new dest    // source
	memcpy(mac1, mac2, sizeof(uint8_t) * 6);
	get_interface_mac(m.interface, mac3);
}


int main(int argc, char *argv[]) {
	packet m;
	int rc;

	init();

	std::vector<route_table_entry> rtable = parse_input_file();
	std::sort(rtable.begin(), rtable.end(), ip_is_greater);
	std::vector<arp_table_entry> arp_table;
	std::queue<packet> packet_queue;

	std::ofstream f;
	f.open("data.out");

	while (1) {
		//std::cout << "I AM HERE WHILE"<<std::endl;
		
		rc = get_packet(&m);
		//std::cout << "I AM HERE PKT"<<std::endl;
		
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			
			struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));
			
			if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST) {
				// Change IPs
				modify_ip(arp_hdr->arp_tpa, arp_hdr->arp_spa);

				// Modify ARP MAC
				modify_mac(arp_hdr->arp_tha, arp_hdr->arp_sha, arp_hdr->arp_sha, m);
				arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);

				// ETHER HDR
				modify_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost, eth_hdr->ether_shost, m);

				// send pack
				send_packet(m.interface, &m); 
				continue;
			}

			std::cout<<"INAINTE DE REPLY"<<std::endl;

			if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {

				std::cout<<"ARP REPLY"<<std::endl;
				arp_table_entry new_entry;
				memcpy(&new_entry.ip, arp_hdr->arp_spa, sizeof(uint8_t) * 4);
				memcpy(new_entry.mac, arp_hdr->arp_sha, sizeof(uint8_t) * 6);

				arp_table.push_back(new_entry);

				while (!packet_queue.empty()) {
					std::cout<<"COADA NEGOALA"<<std::endl;
					packet pkt = packet_queue.front();
					packet_queue.pop();

					struct ether_header *eth_hdr = (struct ether_header *)pkt.payload;
					struct iphdr *ip_hdr = (struct iphdr *)(pkt.payload + sizeof(ether_header));
					struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + sizeof(ether_header) + sizeof(iphdr));
					route_table_entry *bestEntry = get_best_route(ip_hdr->daddr, rtable);

					ip_hdr->ttl--;
					ip_hdr->check = 0;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));
					
					memcpy(eth_hdr->ether_dhost, new_entry.mac, sizeof(uint8_t) * 6);
					get_interface_mac(pkt.interface, eth_hdr->ether_shost);
					pkt.interface = bestEntry->interface;
					send_packet(bestEntry->interface, &pkt);
					continue;
				}

			}

		}
	
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			std::cout << "I AM HERE IP"<<std::endl;
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(ether_header) + sizeof(iphdr));

			uint16_t oldChecksum = ip_hdr->check;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			if (oldChecksum != 0 && oldChecksum != ip_hdr->check) {
				std::cout<<"CHECKSUM SEND" << std::endl;
				continue;
			}

			std::cout<<"DUPA CHECKSUM" << std::endl;

			if (ip_hdr->ttl <= 1) {
				// DONE

				std::swap(ip_hdr->daddr, ip_hdr->saddr);
				ip_hdr->ttl = 120;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				icmp_hdr->type = 11; // htons(ICMP_TIME_EXCEEDED);
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(ether_header);
				std::cout<<"TTL < 1 SEND" << std::endl;
				
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_packet(m.interface, &m);
				continue;
			}

			route_table_entry *bestEntry = get_best_route(ip_hdr->daddr, rtable);
			//std::cout << bestEntry->prefix <<std::endl;
			std::cout<<"DUPA TTL" << std::endl;

			if (bestEntry == nullptr) {
				// DEST UNREACH

				std::swap(ip_hdr->daddr, ip_hdr->saddr);
				ip_hdr->ttl = 120;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				icmp_hdr->type = 3; //htons(ICMP_DEST_UNREACH);
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));
				std::cout<<"DEST UNREACH SEND" << std::endl;

				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(ether_header);
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_packet(m.interface, &m);
				continue;
			}

			std::cout<<"DUPA DEST UNREACH" << std::endl;

			//uint32_t current_ip = 0;;
			//memcpy(&current_ip, get_interface_ip(m.interface), sizeof(uint8_t) * 4);

			struct in_addr ip_addr1;
    		ip_addr1.s_addr = inet_addr(get_interface_ip(m.interface));

			struct in_addr ip_addr2;
    		ip_addr2.s_addr = ip_hdr->daddr;

			std::cout<<inet_ntoa(ip_addr1) <<" "<<inet_ntoa(ip_addr2)<<std::endl;
			std::cout<<ip_addr1.s_addr<<" "<<ip_addr2.s_addr<<std::endl;

			if (icmp_hdr->type == ICMP_ECHO && inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
				std::swap(ip_hdr->daddr, ip_hdr->saddr);
				ip_hdr->ttl = 120;
				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr->protocol = IPPROTO_ICMP;
				ip_hdr->version = 4;
				ip_hdr->ihl = 5;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				icmp_hdr->type = 0; //htons(ICMP_ECHOREPLY);
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				send_packet(m.interface, &m);
				std::cout<<"ECHOREPLY SEND" << std::endl;
				continue;
			}

			// scot entry din tabela arp
			// daca exista, forwardare

			std::cout<<"INAINTE DE ARP ENTRY "<<std::endl;

			arp_table_entry *arp_entry = get_arp_entry(arp_table, ip_hdr->daddr);

			std::cout<<"DUPA ARP ENTRY "<<std::endl;

			if (arp_entry) {
				std::cout<<"ARP ENTRY" << std::endl;
				ip_hdr->ttl--;
				ip_hdr->check = 0;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * 6);
				get_interface_mac(bestEntry->interface, eth_hdr->ether_shost);
				m.interface = bestEntry->interface;
				
				send_packet(bestEntry->interface, &m);
				continue;

			}	else {

				std::cout<<"SA TE FUT IN GURA"<<std::endl;
				m.interface = bestEntry->interface;
				packet_queue.push(m);
				struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));

				uint32_t ip_dest;
				memcpy(&ip_dest, &ip_hdr->daddr, sizeof(uint8_t) * 4);

				arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
				arp_hdr->ea_hdr.ar_hrd = htons(1);
				arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
				arp_hdr->ea_hdr.ar_hln = 6;
				arp_hdr->ea_hdr.ar_pln = 4;

				std::cout<< "MODIF EA HDR"<<std::endl;
				memset(arp_hdr->arp_tha, 0x00, sizeof(uint8_t) * 6);
				get_interface_mac(bestEntry->interface, arp_hdr->arp_sha);
				memcpy(arp_hdr->arp_spa, get_interface_ip(bestEntry->interface), sizeof(uint8_t) * 4);
				memcpy(arp_hdr->arp_tpa, &ip_dest, sizeof(uint8_t) * 4);

				std::cout<< "MODIF ARP HDR"<<std::endl;
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				memset(eth_hdr->ether_dhost, 0xff, sizeof(uint8_t) * 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				std::cout<< "MODIF ETH HDR"<<std::endl;
				m.len = sizeof(ether_arp) + sizeof(iphdr);
				send_packet(bestEntry->interface, &m);
				continue;
			}
			std::cout<<"LOST PKT" << std::endl;
			continue;
		}
	}

	f.close();
}
