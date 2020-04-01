#include "read_data.h"

route_table_entry get_entry (char prefix[], char next_hop[], char mask[], int interface) {
    route_table_entry new_entry;
    new_entry.prefix = inet_addr(prefix);
    new_entry.next_hop = inet_addr(next_hop); 
    new_entry.mask = inet_addr(mask);
    new_entry.interface = interface;

    return new_entry; 
}

std::vector<route_table_entry> parse_input_file() {
	std::ifstream f;
    std::vector<route_table_entry> rtable;

	f.open("rtable.txt");

    char prefix[50], next_hop[50], mask[50];
    int interface;

    while (1) {
        f >> prefix >> next_hop >> mask;
        f >> interface;
        if (f.eof()) {
            break;
        }

		route_table_entry entry = get_entry(prefix, next_hop, mask, interface);
        rtable.push_back(entry);
	}

	f.close();
	fprintf(stderr, "Done parsing router table.\n");
    
    return rtable;
}