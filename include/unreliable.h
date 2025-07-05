#pragma once
#include<cstdint>
#include<iostream>
#include<vector>

struct Result {
    std::string label;
    uint64_t address;
    uint64_t immediate;

    Result(const std::string& l, uint64_t a, uint64_t i)
        : label(l), address(a), immediate(i) {}
};

std::vector<Result> findPatches(const char* filepath);