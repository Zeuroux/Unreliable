#include "parser.h"

inline void parsePE(peparse::parsed_pe* pe, BinaryInfo& info) {
    info.format = FORMAT_PE;
    auto header = pe->peHeader.nt.FileHeader;
    auto machine = header.Machine;
    switch (machine) {
        case peparse::IMAGE_FILE_MACHINE_AMD64:
            info.arch = ARCH_X86;
            info.mode = MODE_64;
            break;
        case peparse::IMAGE_FILE_MACHINE_I386:
            info.arch = ARCH_X86;
            info.mode = MODE_32;
            break;
        default:
            std::cerr << "Unsupported Architecture: " << to_hex_string(machine) << std::endl;
            return;
    }
    peparse::IterSec(pe, [](void* data_ptr, const peparse::VA&, const std::string& sec_name,
        const peparse::image_section_header& s_header, const peparse::bounded_buffer* b) -> int {
            if (sec_name != ".text") return 0;
            auto& data = *static_cast<BinaryInfo*>(data_ptr);
            data.bytes = b->buf;
            data.size = b->bufLen;
            data.virtual_address = s_header.VirtualAddress;
            data.file_offset = s_header.PointerToRawData;
            return 1;
        }, &info);
}

inline void parseElf(ELFIO::elfio& reader, BinaryInfo& info) {
    info.format = FORMAT_ELF;
    auto machine = reader.get_machine();
    switch (machine) {
        case ELFIO::EM_X86_64:
            info.arch = ARCH_X86;
            info.mode = MODE_64;
            break;
        case ELFIO::EM_386:
            info.arch = ARCH_X86;
            info.mode = MODE_32;
            break;
        case ELFIO::EM_AARCH64:
            info.arch = ARCH_AARCH64;
            info.mode = MODE_ARM;
            break;
        default:
            std::cerr << "Unsupported Architecture: " << machine << std::endl;
            return;
    }
    auto sec = reader.sections[".text"];
    if (sec == nullptr) {
        std::cerr << ".text section not found in ELF file\n";
        return;
    }
    info.data.resize(sec->get_size());
    std::memcpy(info.data.data(), sec->get_data(), sec->get_size());
    info.bytes = info.data.data();
    info.size = info.data.size();
    info.virtual_address = sec->get_address();
    info.file_offset = sec->get_address() - sec->get_offset();
}

BinaryInfo parseBinary(const std::string& filepath) {
    auto info = BinaryInfo();
    ELFIO::elfio reader;
    if (reader.load(filepath)) {
        parseElf(reader, info);
    }
    else if (auto pe = peparse::ParsePEFromFile(filepath.c_str())) {
        parsePE(pe, info);
    }
    else {
        std::cout << "Not a valid executable or library" << std::endl;
    }
    return info;
}