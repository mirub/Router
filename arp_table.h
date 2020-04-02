#include "read_data.h"

class arp_table_entry {
public:
    uint32_t ip;
	uint8_t mac[6];

    arp_table_entry() {}

    ~arp_table_entry() {}
};