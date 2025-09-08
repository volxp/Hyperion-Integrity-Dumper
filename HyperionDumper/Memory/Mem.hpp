#pragma once
#include <iostream>
#include <cstdint>


struct proc {
	uintptr_t hyperion;
	void* h;
};
inline proc r;

#pragma region shutcompiler
// thats because we dont want to include Thirdparty headers. 
// Because we arent even defining those fucked functions here, we can simply def them to their type

typedef unsigned long DWORD; // windows.h
typedef void* HANDLE; // windows.h
struct HWND__;
typedef HWND__* HWND;

#pragma endregion



class Memory {
private:
	
public:
	static DWORD getProcessId(const std::string& windowname);
	static HWND getHWND(const std::string& windowname);

	static HANDLE getProcessHandle(const std::string& windowname);
	static HANDLE getProcessHandle(const DWORD pid);
	static HANDLE getProcessHandle(const HWND hwnd);

	static uintptr_t getModuleBaseAddress(const DWORD pid, const std::string& mod);


	template <typename T>
	T read(uintptr_t addr, HANDLE h = r.h);

	template <typename T>
	void write(uintptr_t addr, T val, HANDLE h = r.h);


};