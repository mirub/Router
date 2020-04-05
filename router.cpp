#include "read_data.h"
#include "router.h"
#include "./include/skel.h"

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

		rc = get_packet(&m);
		
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			
			struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));
			
			if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST) {
				// Modify message type
				arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);	

				// Change IPs
				modify_ip(arp_hdr->arp_tpa, arp_hdr->arp_spa);

				// Modify ARP MAC
				modify_mac(arp_hdr->arp_tha, arp_hdr->arp_sha, arp_hdr->arp_sha, m);

				// ETHER HDR
				modify_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost, eth_hdr->ether_shost, m);

				// send pack
				send_packet(m.interface, &m); 
				continue;
			}

			if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
				// Create new entry to ARP Table
				arp_table_entry new_entry;
				memcpy(&new_entry.ip, arp_hdr->arp_spa, sizeof(uint8_t) * 4);
				memcpy(new_entry.mac, arp_hdr->arp_sha, sizeof(uint8_t) * 6);

				arp_table.push_back(new_entry);

				while (!packet_queue.empty()) {
					// Choose next packet to send
					packet pkt = packet_queue.front();
					packet_queue.pop();

					// Split the headers
					struct ether_header *eth_hdr = (struct ether_header *)pkt.payload;
					struct iphdr *ip_hdr = (struct iphdr *)(pkt.payload + sizeof(ether_header));
					struct icmphdr *icmp_hdr = (struct icmphdr *)(pkt.payload + sizeof(ether_header) + sizeof(iphdr));
					route_table_entry *bestEntry = get_best_route(ip_hdr->daddr, rtable);

					// Modify IP header
					change_ip_header(ip_hdr, 1);

					// Modify checksum
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

					// Modify ether header
					modify_mac(eth_hdr->ether_dhost, new_entry.mac, eth_hdr->ether_shost, pkt);

					// Send packet
					pkt.interface = bestEntry->interface;
					send_packet(bestEntry->interface, &pkt);
					continue;
				}

			}

		}
	
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(ether_header) + sizeof(iphdr));

			// Get new checksum
			uint16_t oldChecksum = ip_hdr->check;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			// Verify checksum
			if (oldChecksum != 0 && oldChecksum != ip_hdr->check) {
				continue;
			}

			// Check ttl
			if (ip_hdr->ttl <= 1) {

				modify_ip(&ip_hdr->daddr, &ip_hdr->saddr);
				change_ip_header(ip_hdr, -100);
				change_ip_header_icmp(ip_hdr);
				change_icmp_header(icmp_hdr, 11);

				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(ether_header);

				send_packet(m.interface, &m);
				continue;
			}

			route_table_entry *bestEntry = get_best_route(ip_hdr->daddr, rtable);
			// Check if the packet can be sent
			if (bestEntry == nullptr) {

				modify_ip(&ip_hdr->daddr, &ip_hdr->saddr);
				change_ip_header(ip_hdr, -100);
				change_ip_header_icmp(ip_hdr);
				change_icmp_header(icmp_hdr, 3);

				m.len = sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(ether_header);
				
				modify_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost, eth_hdr->ether_shost, m);
				send_packet(m.interface, &m);
				continue;
			}

			// Check if the packet should be received by the router
			if (icmp_hdr->type == ICMP_ECHO && inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {

				modify_ip(&ip_hdr->daddr, &ip_hdr->saddr);
				change_ip_header(ip_hdr, -100);
				change_ip_header_icmp(ip_hdr);
				change_icmp_header(icmp_hdr, 0);

				modify_mac(eth_hdr->ether_dhost, eth_hdr->ether_shost, eth_hdr->ether_shost, m);
				send_packet(m.interface, &m);
				continue;
			}

			arp_table_entry *arp_entry = get_arp_entry(arp_table, ip_hdr->daddr);
			// Check if there is an ARP table entry
			if (arp_entry) {
				change_ip_header(ip_hdr, 1);

				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

				modify_mac(eth_hdr->ether_dhost, arp_entry->mac, eth_hdr->ether_shost, m);

				m.interface = bestEntry->interface;
				send_packet(bestEntry->interface, &m);
				continue;

			}	else {
				// Add packet to queue and send ARP Request 
				m.interface = bestEntry->interface;
				packet_queue.push(m);
				struct ether_arp *arp_hdr = (struct ether_arp *)(m.payload + sizeof(struct ether_header));

				uint32_t ip_dest;
				memcpy(&ip_dest, &ip_hdr->daddr, sizeof(uint8_t) * 4);

				change_arp_inexistent_entry(arp_hdr);

				memset(arp_hdr->arp_tha, 0x00, sizeof(uint8_t) * 6);
				get_interface_mac(bestEntry->interface, arp_hdr->arp_sha);

				memcpy(arp_hdr->arp_spa, get_interface_ip(bestEntry->interface), sizeof(uint8_t) * 4);
				memcpy(arp_hdr->arp_tpa, &ip_dest, sizeof(uint8_t) * 4);

				eth_hdr->ether_type = htons(ETHERTYPE_ARP);
				memset(eth_hdr->ether_dhost, 0xff, sizeof(uint8_t) * 6);
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				m.len = sizeof(ether_arp) + sizeof(iphdr);
				send_packet(bestEntry->interface, &m);
				continue;
			}
			continue;
		}
	}

	f.close();
}
