#include <Windows.h> // fuck you compiler LMAO
#include "dis.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <iostream>
#include <optional>
#include <string>
#include <sstream>
#include <cstdint>


#pragma comment(lib, "Psapi.lib") 


std::vector<uintptr_t> disasm::SigScan(const std::string& pattern, HANDLE h) {
    std::vector<uintptr_t> results;

    auto patternToBytes = [](const std::string& pattern) {
        std::vector<std::optional<uint8_t>> bytes;
        std::istringstream iss(pattern);
        std::string byteStr;
        while (iss >> byteStr) {
            if (byteStr == "?" || byteStr == "??")
                bytes.push_back(std::nullopt);
            else
                bytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
        }
        return bytes;
        };

    uintptr_t base = r.hyperion;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(h, (HMODULE)base, &modInfo, sizeof(modInfo))) {
        printf("GetModuleInformation failed: %lu\n", GetLastError());
        return results;
    }

    auto patternBytes = patternToBytes(pattern);
    const size_t patternSize = patternBytes.size();
    uintptr_t moduleEnd = base + modInfo.SizeOfImage;
    uintptr_t currentAddress = base;

    while (currentAddress < moduleEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(h, (LPCVOID)currentAddress, &mbi, sizeof(mbi))) {
            break;
        }

        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY | PAGE_READWRITE)) &&
            !(mbi.Protect & PAGE_GUARD)) {

            std::vector<uint8_t> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(h, mbi.BaseAddress, buffer.data(), buffer.size(), &bytesRead)) {
                for (size_t i = 0; i <= bytesRead - patternSize; i++) {
                    bool found = true;
                    for (size_t j = 0; j < patternSize; j++) {
                        if (patternBytes[j].has_value() && buffer[i + j] != patternBytes[j].value()) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        results.push_back(reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i);
                    }
                }
            }
            else {
                printf("ReadProcessMemory failed at 0x%p: %lu\n", mbi.BaseAddress, GetLastError());
            }
        }
        // made by volxphy
        currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return results;
}


uintptr_t disasm::findNext(const uintptr_t start, ZydisMnemonic target, int skip, ZydisOperandType operandTypeFilter, HANDLE h) {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    const size_t maxScan = 0x1000; // one page
    std::vector<uint8_t> buffer(maxScan);
    ReadProcessMemory(h, (LPCVOID)start, buffer.data(), buffer.size(), nullptr);

    size_t offset = 0;
    while (offset < buffer.size()) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer.data() + offset, buffer.size() - offset, &instruction, operands))) {
            if (instruction.mnemonic == target) {
                bool matchesOperandFilter = true;
                if (operandTypeFilter != ZYDIS_OPERAND_TYPE_UNUSED) {
                    matchesOperandFilter = false;
                    for (int i = 0; i < instruction.operand_count; ++i) {
                        if (operands[i].type == operandTypeFilter) {
                            matchesOperandFilter = true;
                            break;
                        }
                    }
                }

                if (matchesOperandFilter) {
                    if (skip == 0) {
                        return start + offset;
                    }
                    else {
                        skip--;
                    }
                }
            }
            offset += instruction.length;
        }
        else {
            offset += 1;
        }
    }
    return 0;
}

bool disasm::isMovRdx(const uintptr_t addr, HANDLE h) {
    uint8_t buffer[16];
    SIZE_T bytesRead = 0;

    uintptr_t readAddr = (addr >= 8) ? addr - 8 : addr;
    if (!ReadProcessMemory(h, (LPCVOID)readAddr, buffer, sizeof(buffer), &bytesRead)) {
        return false;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    for (int offset = 0; offset < 8 && offset < bytesRead - 2; offset++) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    (operands[0].reg.value == ZYDIS_REGISTER_RDX ||
                        operands[0].reg.value == ZYDIS_REGISTER_RCX)) {

                    uintptr_t instrStart = readAddr + offset;
                    if (addr >= instrStart && addr < instrStart + instruction.length) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

uintptr_t disasm::rebase(uintptr_t addr) {
    if (!r.hyperion) return 0x0;

    return (addr - r.hyperion);
}

uintptr_t disasm::findPrevInstr(const uintptr_t addr, HANDLE h) {
    const size_t maxLookback = 64;
    uint8_t buffer[maxLookback];
    SIZE_T bytesRead = 0;

    uintptr_t readAddr = (addr >= maxLookback) ? addr - maxLookback : 0;
    size_t actualLookback = addr - readAddr;

    if (!ReadProcessMemory(h, (LPCVOID)readAddr, buffer, actualLookback, &bytesRead)) {
        return 0;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    uintptr_t lastValidInstrAddr = 0;
    size_t offset = 0;

    while (offset < bytesRead) {
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, buffer + offset, bytesRead - offset, &instruction, operands))) {
            uintptr_t currentInstrAddr = readAddr + offset;
            uintptr_t nextInstrAddr = currentInstrAddr + instruction.length;

            if (nextInstrAddr == addr) {
                return currentInstrAddr;
            }

            if (currentInstrAddr < addr) {
                lastValidInstrAddr = currentInstrAddr;
            }

            offset += instruction.length;
        }
        else {
            offset += 1;
        }
    }

    return lastValidInstrAddr;
}