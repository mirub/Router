#include "./include/skel.h"
#pragma once
#include <stdio.h>
#include <unistd.h>
#include <bits/stdc++.h>

class route_table_entry {
public: 	
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;

	route_table_entry() {}

	~route_table_entry() {}
};

std::vector<route_table_entry> parse_input_file();
