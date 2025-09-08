#pragma once
#include <iostream>
#include <vector>
#include <Zydis/Zydis.h>
#include "../Memory/Mem.hpp"


class disasm {
private:

public:
	static std::vector<uintptr_t> SigScan(const std::string& pattern, HANDLE h = r.h);
	static uintptr_t findNext(const uintptr_t start, ZydisMnemonic target, int skip = 0, ZydisOperandType operandTypeFilter = ZYDIS_OPERAND_TYPE_UNUSED, HANDLE h = r.h);
	static bool isMovRdx(const uintptr_t addr, HANDLE h = r.h);
	static uintptr_t rebase(const uintptr_t addr);
	static uintptr_t findPrevInstr(const uintptr_t addr, HANDLE h = r.h);
};