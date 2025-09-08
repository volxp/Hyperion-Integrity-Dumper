#include "Mem.hpp"
#include <Windows.h>
#include <string>
#include <TlHelp32.h>




DWORD Memory::getProcessId(const std::string& windowname) {
	HWND h = FindWindowA(nullptr, windowname.c_str());
	if (!h) return 0;

	DWORD pid;
	GetWindowThreadProcessId(h, &pid);
	if (!pid) return 0;
	return pid;
}

HWND Memory::getHWND(const std::string& windowname) {
	HWND h = FindWindowA(nullptr, windowname.c_str());
	if (!h) return nullptr;
	return h;
}

HANDLE Memory::getProcessHandle(const std::string& windowname) {
	DWORD pid = getProcessId(windowname);
	if (!pid) return nullptr;
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) return nullptr;
	r.h = h;
	return h;
}
HANDLE Memory::getProcessHandle(const DWORD pid) {
	if (!pid) return nullptr;
	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) return nullptr;
	r.h = h;
	return h;
}
HANDLE Memory::getProcessHandle(const HWND hwnd) {
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	if (!pid) return nullptr;

	HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!h) return nullptr;
	r.h = h;
	return h;
} 

uintptr_t Memory::getModuleBaseAddress(const DWORD pid, const std::string& modName) {
	uintptr_t modBaseAddr = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(MODULEENTRY32);

		if (Module32First(hSnap, &modEntry)) {
			do {
				if (modName == modEntry.szModule) {
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}



template <typename T>
T Memory::read(uintptr_t addr, HANDLE h) {
	T buf{};
	ReadProcessMemory(h, (LPCVOID)addr, &buf, sizeof(T), nullptr);
	return buf;
}

template <typename T>
void Memory::write(uintptr_t addr, T val, HANDLE h) {
	WriteProcessMemory(h, (LPVOID)addr, (LPCVOID)val, sizeof(T), nullptr);
}

