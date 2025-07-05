#include <iostream>
#include <cstdint>
#include <inttypes.h>
#include <vector>

uint64_t find_closest_pair(const uint64_t* data, size_t size);
uint64_t find_max_less_than_fast(const uint64_t* data, size_t size, uint64_t target);
uint64_t find_min_greater_than_fast(const uint64_t* data, size_t size, uint64_t target);
void find_indices_with_target(const std::pair<uint64_t, uint64_t>* data, size_t size, uint64_t target_value, std::vector<size_t>& out_indices);