#include "searchers.h"

uint64_t find_closest_pair(const uint64_t* data, size_t size) {
    if (size <= 2)
        return size == 0 ? 0 : data[0];
    uint64_t minDiff = UINT64_MAX;
    uint64_t first = data[0];
    for (size_t i = 1; i < size; ++i) {
        uint64_t diff = data[i] - data[i - 1];
        if (diff < minDiff) {
            minDiff = diff;
            first = data[i - 1];
        }
    }
    return first;
}

uint64_t find_max_less_than_fast(const uint64_t* data, size_t size, uint64_t target) {
    size_t low = 0, high = size;
    while (low < high) {
        size_t mid = low + ((high - low) >> 1);
        if (data[mid] < target)
            low = mid + 1;
        else
            high = mid;
    }
    return (low == 0) ? 0 : data[low - 1];
}

uint64_t find_min_greater_than_fast(const uint64_t* data, size_t size, uint64_t target) {
    size_t low = 0, high = size;
    while (low < high) {
        size_t mid = low + ((high - low) >> 1);
        if (data[mid] < target)
            low = mid + 1;
        else
            high = mid;
    }
    return (low == size) ? 0 : data[low];
}

void find_indices_with_target(const std::pair<uint64_t, uint64_t>* data, size_t size, uint64_t target_value, std::vector<size_t>& out_indices) {
    out_indices.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        if (data[i].second == target_value)
            out_indices.emplace_back(i);
    }
}