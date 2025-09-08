#include <iostream>
#include "Disasm/dis.hpp"
#include "Log.h"
#include <chrono>


void printAddress(const std::string& name, const uintptr_t addr) {
	printf("inline uintptr_t %s = 0x%llx\n", name.c_str(), disasm::rebase(addr));
}

void printArray(const std::string& name, std::vector<uintptr_t> res) {
	printf("inline uint64_t %s[%d] = {\n    ", name.c_str(), res.size());
	for (size_t i = 0; i < res.size(); ++i) {
		std::cout << "0x" << std::hex << res[i];
		if (i != res.size() - 1) {
			std::cout << ", ";
		}
		if ((i + 1) % 3 == 0 && i != res.size() - 1) {
			std::cout << "\n    ";
		}
	}
	printf("\n};\n");
}

void dump() {
	uintptr_t _generalIntegrityCheck = disasm::SigScan("49 39 D7 75 ? 45 31 E4").data()[0];
	if (_generalIntegrityCheck) {
		printAddress("generalIntegrityCheck", _generalIntegrityCheck);
	}
	uintptr_t _controlFlowGuard = disasm::SigScan("49 BB FF FF FF FF FF 7F 00 00").data()[0];
	if (_controlFlowGuard) {
		printAddress("controlFlowGuard", _controlFlowGuard);
	}
	uintptr_t _whitelistCheck = disasm::SigScan("83 E0 02 09 D0 83 F8 03").data()[0];
	if (_whitelistCheck) {
		printAddress("whitelistCheckCMP", _whitelistCheck);
	}
	uintptr_t _consoleCheck = disasm::SigScan("48 83 78 ? ? 0F 95 C0").data()[0];
	if (_consoleCheck) {
		printAddress("consoleCheck", _consoleCheck);
	}
	uintptr_t _icebp = disasm::SigScan("41 F7 C0 ? ? ? ? 0F 85").data()[0];
	if (_icebp) {
		printAddress("icebpCMP", _icebp);
	}



}

void dumpSubChecks() {
	std::vector<uint64_t> subResults{};
	std::vector<uintptr_t> filtered{};

	std::vector<uintptr_t> _subChecks = disasm::SigScan("A5 ?? 6C AA CC 8D 35 2D");
	Log::debug("Found %d results for subChecks!\n", _subChecks.size());

	for (const auto sub : _subChecks) {
		if ((disasm::rebase(sub) > 0x400000) && disasm::isMovRdx(sub)) {
			filtered.push_back(sub);
		}
	}

	static int hits = 0;
	for (const auto addr : filtered) {
		if (hits >= 12)
			continue;
		uintptr_t end = disasm::findNext(addr, ZYDIS_MNEMONIC_JNZ);
		uintptr_t target = disasm::findPrevInstr(end);
		uintptr_t expected = disasm::findNext(target, ZYDIS_MNEMONIC_CMP);
		if (expected == target) {
			subResults.push_back(disasm::rebase(target));
			hits += 1;
		}
	}


	printArray("subIntegrityChecks", subResults);
}

int main()
{
	DWORD pid = Memory::getProcessId("Roblox");
	if (!pid) {
		Log::error("Failed to get PID! is Roblox open?");
		std::cin.get();
		exit(EXIT_FAILURE);
	}
	Log::info("Roblox Found with PID: %d", pid);
	HANDLE h = Memory::getProcessHandle(pid);
	if (!h) {
		Log::error("Failed to attach!");
		std::cin.get();
		exit(EXIT_FAILURE);
	}
	r.hyperion = Memory::getModuleBaseAddress(pid, "RobloxPlayerBeta.dll");
	Log::debug("Hyperion Base address: 0x%llx", r.hyperion);

	Log::warn("Attempting to dump IntegrityChecks...");
	Log::info("REBASED TO 0x0");

	auto start = std::chrono::high_resolution_clock::now();
	Log::debug("Dumping Sub-IntegrityChecks...");
	dumpSubChecks();
	dump();

	printf("\n\n\n");
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> duration = end - start;
	Log::info("Took %.3f seconds!", duration.count());
	Log::info("Made by Volxphy!");

	std::cin.get();
	return 0;

}