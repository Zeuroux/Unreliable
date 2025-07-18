#pragma once
#include<cstdint>
#include<iostream>
#include<vector>
#include <functional>

#define COMBINE_HEX(high, low) (((high) << 16) | (low))
#define DECIMAL_TO_HEX(value) ( ((uint32_t)(value)) & 0xFFFF )
#define GET_VALUE(max, min) (COMBINE_HEX(DECIMAL_TO_HEX(max), DECIMAL_TO_HEX(min)))

struct Result {
    std::string label;
    uint64_t address;
    uint64_t immediate;

    Result(std::string l, uint64_t a, uint64_t i)
        : label(std::move(l)), address(a), immediate(i) {}
};

struct DimensionInfo {
    enum Identifier { End, Nether, Overworld } identifier;
    int min = 0;
    int max;

    DimensionInfo(Identifier id, int minValue, int maxValue)
        : identifier(id), min(minValue), max(maxValue) {}
};


std::vector<Result> findPatches(const char* filepath, std::vector<DimensionInfo> dimInfo = {{DimensionInfo::End, 0, 256}, {DimensionInfo::Nether, 0, 128}, {DimensionInfo::Overworld, -64, 320}}, std::function<void(int)> progressCallback = nullptr, std::function<void(bool, std::string)> logCallback = nullptr);