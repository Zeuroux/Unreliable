#include <iostream>
#include <unordered_set>
#include <map>
#include <Zydis/Zydis.h>

struct PEDecodeConfig {
    ZydisMachineMode machineMode;
    ZydisStackWidth stackWidth;
    ZydisMnemonic startAfterRetMnemonic;
    int previousCallOffset;
};

constexpr PEDecodeConfig Pe64Config{
    ZYDIS_MACHINE_MODE_LONG_64,
    ZYDIS_STACK_WIDTH_64,
    ZYDIS_MNEMONIC_MOV,
    1
};

constexpr PEDecodeConfig Pe32Config{
    ZYDIS_MACHINE_MODE_LEGACY_32,
    ZYDIS_STACK_WIDTH_32,
    ZYDIS_MNEMONIC_PUSH,
    2
};
