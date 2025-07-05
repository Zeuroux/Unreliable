#include <unreliable.h>
#include "decoders/arm64.h"
#include "utils/searchers.h"
#include "parser.h"
#include "definitions.h"

template<const PEDecodeConfig& config>
inline std::vector<Result> GetPEx86(const BinaryInfo& info, const std::map<uint64_t, std::string>& dimensions) {
    const uint8_t* data = info.bytes;
    uint64_t address = info.virtual_address;
    ZyanUSize offset = 0x1000 - info.file_offset;
    const ZyanUSize buffer_size = info.size;

    ZydisDecoder decoder;
    ZydisDisassembledInstruction instruction;
    ZydisDecoderContext ctx;
    ZydisDecoderInit(&decoder, config.machineMode, config.stackWidth);

    std::vector<std::pair<uint64_t, uint64_t>> calls;
    std::vector<uint64_t> starts;

    std::vector<uint64_t> importantImmediates = { 0x42100000 };
    for (const auto& [key, _] : dimensions) {
        importantImmediates.emplace_back(key);
    }
    std::unordered_set<uint64_t> allowedImmediates(importantImmediates.begin(), importantImmediates.end());
    std::unordered_map<uint64_t, std::vector<uint64_t>> movsMap;
    bool isLastRet = false;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < buffer_size) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &ctx, data + offset, buffer_size - offset, &instruction.info))) {
            const auto mnemonic = instruction.info.mnemonic;
            const auto instrLength = instruction.info.length;
            const auto nextAddress = address + instrLength;

            switch (mnemonic) {
                case ZYDIS_MNEMONIC_RET:
                    isLastRet = true;
                    break;
                case ZYDIS_MNEMONIC_MOV:
                case ZYDIS_MNEMONIC_CALL:
                case ZYDIS_MNEMONIC_PUSH:
                    if (mnemonic == config.startAfterRetMnemonic && isLastRet) {
                        starts.emplace_back(address);
                        isLastRet = false;
                        break;
                    }
                    else if (mnemonic == ZYDIS_MNEMONIC_MOV || mnemonic == ZYDIS_MNEMONIC_CALL) {
                        ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction.info, operands, instruction.info.operand_count);

                        for (uint8_t i = 0; i < instruction.info.operand_count; ++i) {
                            const auto& op = operands[i];
                            if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                                continue;

                            if (mnemonic == ZYDIS_MNEMONIC_CALL && op.imm.is_relative) {
                                calls.emplace_back(address, nextAddress + op.imm.value.s);
                            }
                            else if (allowedImmediates.count(op.imm.value.u)) {
                                movsMap[op.imm.value.u].emplace_back(address);
                            }
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        offset += instruction.info.length;
        address += instruction.info.length;
    }
    std::vector<Result> results;
    const uint64_t firstImportantImmediate = importantImmediates[0];
    auto PWMC = movsMap[firstImportantImmediate];
    auto WMC = find_closest_pair(PWMC.data(), PWMC.size());
    auto DCF = find_max_less_than_fast(starts.data(), starts.size(), WMC);
    std::cout << "DCF: 0x" << std::hex << DCF << std::dec << std::endl;

    std::vector<size_t> callIndices;
    find_indices_with_target(calls.data(), calls.size(), DCF, callIndices);

    uint64_t overworldMovImm = 0;
    for (const auto& [imm, label] : dimensions) {
        if (label == "overworld") {
            overworldMovImm = imm;
            break;
        }
    }

    for (const auto index : callIndices) {
        const auto& call = calls[index];
        uint64_t closestMovAddr = 0;
        uint64_t closestMovImm = 0;
        for (const auto& [imm, _] : dimensions) {
            const auto& movsVec = movsMap[imm];
            const uint64_t* movsData = movsVec.data();
            const size_t movsSize = movsVec.size();

            const uint64_t it = find_max_less_than_fast(movsData, movsSize, call.first);
            if (it > closestMovAddr) {
                closestMovAddr = it;
                closestMovImm = imm;
            }
        }

        const auto& previousCall = calls[index - config.previousCallOffset];

        uint64_t resultAddr = 0;
        uint64_t resultImm = 0;
        uint64_t closestOverworldMovAddr = 0;

        if (previousCall.first > closestMovAddr) {
            const auto& overworldMovs = movsMap[overworldMovImm];
            resultAddr = find_min_greater_than_fast(overworldMovs.data(), overworldMovs.size(), previousCall.second);
            resultImm = overworldMovImm;
        }
        else {
            resultAddr = closestMovAddr;
            resultImm = closestMovImm;
        }

        if (overworldMovImm != 0 && resultImm != overworldMovImm) {
            uint64_t lastStart = find_max_less_than_fast(starts.data(), starts.size(), call.first);
            const auto& overworldMovs = movsMap[overworldMovImm];
            closestOverworldMovAddr = find_max_less_than_fast(overworldMovs.data(), overworldMovs.size(), call.first);
            if (closestOverworldMovAddr > lastStart) {
                resultAddr = closestOverworldMovAddr;
                resultImm = overworldMovImm;
            }
        }

        results.emplace_back(dimensions.at(resultImm), resultAddr, resultImm);
    }

    return results;
}

inline std::vector<Result> GetELFx86(const BinaryInfo& info, const std::map<uint64_t, std::string>& dimensions) {
    const uint8_t* data = info.bytes;
    uint64_t address = info.virtual_address;
    ZyanUSize offset = info.file_offset;
    const ZyanUSize buffer_size = info.size;

    ZydisDecoder decoder;
    ZydisDisassembledInstruction instruction;
    ZydisDecoderContext ctx;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    std::vector<std::pair<uint64_t, uint64_t>> calls;
    std::vector<uint64_t> starts;

    std::vector<uint64_t> importantImmediates = { 0x42100000 };
    for (const auto& [key, _] : dimensions) {
        importantImmediates.emplace_back(key);
    }
    std::unordered_set<uint64_t> allowedImmediates(importantImmediates.begin(), importantImmediates.end());
    std::unordered_map<uint64_t, std::vector<uint64_t>> movsMap;
    bool isLastRet = false;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

    while (offset < buffer_size) {
        if (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, &ctx, data + offset, buffer_size - offset, &instruction.info))) {
            const auto mnemonic = instruction.info.mnemonic;
            const auto instrLength = instruction.info.length;
            const auto nextAddress = address + instrLength;

            switch (mnemonic) {
                case ZYDIS_MNEMONIC_RET:
                    isLastRet = true;
                    break;
                case ZYDIS_MNEMONIC_PUSH:
                    if (isLastRet) {
                        starts.emplace_back(address);
                        isLastRet = false;
                    }
                    break;
                case ZYDIS_MNEMONIC_MOV:
                case ZYDIS_MNEMONIC_CALL:
                    ZydisDecoderDecodeOperands(&decoder, &ctx, &instruction.info, operands, instruction.info.operand_count);
                    for (uint8_t i = 0; i < instruction.info.operand_count; ++i) {
                        const auto& op = operands[i];
                        if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                            continue;

                        if (mnemonic == ZYDIS_MNEMONIC_CALL && op.imm.is_relative) {
                            calls.emplace_back(address, nextAddress + op.imm.value.s);
                        }
                        else if (allowedImmediates.count(op.imm.value.u)) {
                            movsMap[op.imm.value.u].emplace_back(address);
                        }
                    }
                    break;
                default:
                    break;
            }
        }
        offset += instruction.info.length;
        address += instruction.info.length;
    }
    std::vector<Result> results;

    const uint64_t firstImportantImmediate = importantImmediates[0];
    auto PWMC = movsMap[firstImportantImmediate];
    auto WMC = find_closest_pair(PWMC.data(), PWMC.size());
    auto DCF = find_max_less_than_fast(starts.data(), starts.size(), WMC);
    std::cout << "DCF: 0x" << std::hex << DCF << std::dec << std::endl;

    std::vector<size_t> callIndices;
    find_indices_with_target(calls.data(), calls.size(), DCF, callIndices);

    uint64_t overworldMovImm = 0;
    for (const auto& [imm, label] : dimensions) {
        if (label == "overworld") {
            overworldMovImm = imm;
            break;
        }
    }

    for (const auto index : callIndices) {
        const auto& call = calls[index];

        uint64_t closestMovAddr = 0;
        uint64_t closestMovImm = 0;
        for (const auto& [imm, _] : dimensions) {
            const auto& movsVec = movsMap[imm];
            const uint64_t* movsData = movsVec.data();
            const size_t movsSize = movsVec.size();

            const uint64_t it = find_max_less_than_fast(movsData, movsSize, call.first);
            if (it > closestMovAddr) {
                closestMovAddr = it;
                closestMovImm = imm;
            }
        }

        uint64_t resultAddr = closestMovAddr;
        uint64_t resultImm = closestMovImm;
        uint64_t closestOverworldMovAddr = 0;

        if (overworldMovImm != 0 && resultImm != overworldMovImm) {
            uint64_t lastStart = find_max_less_than_fast(starts.data(), starts.size(), call.first);
            const auto& overworldMovs = movsMap[overworldMovImm];
            closestOverworldMovAddr = find_max_less_than_fast(overworldMovs.data(), overworldMovs.size(), call.first);
            if (closestOverworldMovAddr > lastStart) {
                resultAddr = closestOverworldMovAddr;
                resultImm = overworldMovImm;
            }
        }

        results.emplace_back(dimensions.at(resultImm), resultAddr, resultImm);
    }

    return results;
}

inline std::vector<Result> GetELFArm64(const BinaryInfo& info, const std::map<uint64_t, std::string>& dimensions) {
    const uint8_t* data = info.bytes;
    uint64_t address = info.virtual_address;
    size_t offset = info.file_offset;
    const size_t size = info.size;

    std::vector<std::pair<uint64_t, uint64_t>> calls;
    std::vector<uint64_t> starts;
    std::unordered_map<uint64_t, std::vector<uint64_t>> movsMap;

    std::unordered_set<uint64_t> allowedImms = { 0x42100000 };
    for (auto&& [imm, _] : dimensions) allowedImms.insert(imm);

    bool lastWasRet = false;

    while (offset + 4 <= size) {
        uint32_t instr = data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24);
        if (auto dec = decodeArm64(instr, address)) {
            switch (dec->cls) {
                case Decoded::BL:    calls.emplace_back(dec->addr, dec->addr + dec->imm); break;
                case Decoded::MOVZ:  if (allowedImms.contains(dec->imm)) movsMap[dec->imm].emplace_back(dec->addr); break;
                case Decoded::RET:   lastWasRet = true; break;
                case Decoded::SUB:   if (lastWasRet) { starts.emplace_back(dec->addr); lastWasRet = false; } break;
                default: break;
            }
        }
        offset += 4; address += 4;
    }
    std::vector<Result> results;

    auto& primaryMovs = movsMap[0x42100000];
    auto WMC = find_closest_pair(primaryMovs.data(), primaryMovs.size());
    auto DCF = find_max_less_than_fast(starts.data(), starts.size(), WMC);
    std::cout << "DCF: 0x" << std::hex << DCF << std::dec << '\n';

    std::vector<size_t> callIndices;
    find_indices_with_target(calls.data(), calls.size(), DCF, callIndices);

    for (auto i : callIndices) {
        const auto& [from, to] = calls[i];
        auto lastStart = find_max_less_than_fast(starts.data(), starts.size(), from);

        for (const auto& [imm, label] : dimensions) {
            auto& movs = movsMap[imm];
            if (movs.empty()) continue;

            auto it = find_max_less_than_fast(movs.data(), movs.size(), from);
            if (it > lastStart){
                results.emplace_back(label, it, imm);
            }
        }
    }

    return results;
}

std::vector<Result> findPatches(const char* filepath) {
    const std::map<uint64_t, std::string> standard = {
        {0x1000000, "end"}, {0x800000, "nether"}, {0x140ffc0, "overworld"}
    }, elf64 = {
        {0x1000000, "end"}, {0x800000, "nether"}, {0xffc0, "overworld_min"}, {0x140ffc0, "overworld"}
    }, arm64 = {
        {0x1000000, "end"}, {0x800000, "nether"}, {0xffc0, "overworld_min"}, {0x140, "overworld_max"}
    };

    std::vector<Result> results;
    auto info = parseBinary(filepath);
    switch (info.format) {
        case FORMAT_PE:
            if (info.arch == ARCH_X86)
                results = info.mode == MODE_64 ? GetPEx86<Pe64Config>(info, standard) : GetPEx86<Pe32Config>(info, standard);
            break;
        case FORMAT_ELF:
            if (info.arch == ARCH_X86)
                results = GetELFx86(info, info.mode == MODE_64 ? elf64 : standard);
            else if (info.arch == ARCH_AARCH64)
                results = GetELFArm64(info, arm64);
            break;
        default:
            std::cerr << "Unsupported format: " << info.format << std::endl;
    }

    return results;
}