#include <iostream>
#include <unordered_set>
#include <map>
#include <Zydis/Zydis.h>

struct ZydisConfig {
    ZydisMachineMode machineMode;
    ZydisStackWidth stackWidth;
};

constexpr ZydisConfig ZydisConfig64{
    ZYDIS_MACHINE_MODE_LONG_64,
    ZYDIS_STACK_WIDTH_64,
};

constexpr ZydisConfig ZydisConfig32{
    ZYDIS_MACHINE_MODE_LEGACY_32,
    ZYDIS_STACK_WIDTH_32,
};

struct PEDecodeConfig {
    ZydisConfig zydis;
    ZydisMnemonic startAfterRetMnemonic;
    int previousCallOffset;
};

constexpr PEDecodeConfig Pe64Config{
    ZydisConfig64,
    ZYDIS_MNEMONIC_MOV,
    1
};

constexpr PEDecodeConfig Pe32Config{
    ZydisConfig32,
    ZYDIS_MNEMONIC_PUSH,
    2
};

inline const char* ToString(DimensionInfo::Identifier id) {
    switch (id) {
        case DimensionInfo::End: return "End";
        case DimensionInfo::Nether: return "Nether";
        case DimensionInfo::Overworld: return "Overworld";
        default: return "Unknown";
    }
}
