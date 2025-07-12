#pragma once
#include<cstdint>
#include<iostream>
#include<vector>
#include <functional>

struct Result {
    std::string label;
    uint64_t address;
    uint64_t immediate;

    Result(const std::string& l, uint64_t a, uint64_t i)
        : label(l), address(a), immediate(i) {}
};

struct DimensionInfo {
    enum Identifier { End, Nether, Overworld } identifier;
    int min = 0;
    int max;

    DimensionInfo(Identifier id, int minValue, int maxValue)
        : identifier(id), min(minValue), max(maxValue) {}
};


std::vector<Result> findPatches(const char* filepath, std::function<void(int)> progressCallback = nullptr, std::vector<DimensionInfo> dimInfo = {{DimensionInfo::End, 0, 256}, {DimensionInfo::Nether, 0, 128}, {DimensionInfo::Overworld, -64, 320}});