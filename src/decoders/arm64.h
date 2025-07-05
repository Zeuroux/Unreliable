#include<cstdint>
#include<optional>

struct Decoded {
    enum Class { BL, RET, MOVZ, SUB, UNKNOWN } cls;
    uint64_t addr;
    int64_t  imm;
};

std::optional<Decoded> decodeArm64(uint32_t instr, uint64_t addr);