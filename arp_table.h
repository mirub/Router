#include "read_data.h"

class arp_table_entry {
public:
    __u32 ip;
	uint8_t mac[6];

    arp_table_entry() {}

    ~arp_table_entry() {}
};