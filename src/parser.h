#include <elfio/elfio.hpp>
#include <pe-parse/parse.h>

enum Architecture {
    ARCH_UNKNOWN,
    ARCH_X86,
    ARCH_AARCH64
};

enum Mode {
    MODE_UNKNOWN,
    MODE_32,
    MODE_64,
    MODE_ARM
};

enum Format {
    FORMAT_PE,
    FORMAT_ELF,
    FORMAT_UNKNOWN
};

struct BinaryInfo {
    std::vector<uint8_t> data;
    Format format;
    Architecture arch;
    Mode mode;
    const uint8_t* bytes;
    size_t size;
    uint64_t virtual_address;
    uint64_t file_offset;
};


using ELFIO::to_hex_string;

inline void parsePE(peparse::parsed_pe* pe, BinaryInfo& info, std::function<void(bool, std::string)> logCallback);
inline void parseElf(ELFIO::elfio& reader, BinaryInfo& info, std::function<void(bool, std::string)> logCallback);
BinaryInfo parseBinary(const std::string& filepath, std::function<void(bool, std::string)> logCallback);