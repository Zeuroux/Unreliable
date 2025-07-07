#include "architectures.h"

std::optional<Decoded> decodeArm64(uint32_t instr, uint64_t addr) {
    if ((instr >> 26) == 0b100101) {
        int32_t imm26 = instr & 0x03FFFFFF;
        if (imm26 & 0x02000000) imm26 |= 0xFC000000;
        return Decoded{Decoded::BL, addr, imm26 << 2};
    }

    if ((instr & 0xFFFFFC1F) == 0xD65F0000) {
        return Decoded{Decoded::RET, addr, 0};
    }

    if ((instr >> 23) == 0b010100101) {
        uint32_t imm16 = (instr >> 5) & 0xFFFF;
        uint32_t hw    = (instr >> 21) & 0x3;
        uint64_t value = uint64_t(imm16) << (hw * 16);
        return Decoded{Decoded::MOVZ, addr, int64_t(value)};
    }

    if ((instr >> 24) == 0b11010001) {
        uint32_t imm12 = (instr >> 10) & 0xFFF;
        return Decoded{Decoded::SUB, addr, int64_t(imm12)};
    }

    return std::nullopt;
}