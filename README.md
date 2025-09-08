# Roblox IntegrityCheck Dumper

Dumps: This tool scans for the **Roblox's Hyperion integrityChecks**

---

## Features
- Signature scanning for key checks: `generalIntegrityCheck`, `consoleCheck`, `icebp`, `whitelistCheck`, `controlFlowGuard`
- Dumps sub-integrity checks with pattern filtering
- Tracks execution time
- Logging levels: `debug`, `info`, `warn`, `error`
- Works with `RobloxPlayerBeta.dll` and `RobloxPlayerBeta.exe`

---

## Project Structure
- `main.cpp` → Entry point, process attach, and dump logic  
- `Disasm/dis.hpp` → Signature scanning and disassembly utilities  
- `Log.h` → Logging system  

---

## Usage
1. Clone the repository:
    ```bash
    git clone https://github.com/volxp/HyperionChecks-Dumper.git
    cd HyperionChecks-Dumper
    ```
2. Build the project (MSVC).  
3. Start Roblox.  
4. Run the binary:
    ```bash
    HyperionDumper.exe
    ```
5. Check the output — dumped addresses will appear in the console.

---

## Example Output
```cpp
[2025-09-08 14:12:16][INFO] Roblox Found with PID: 23684
[2025-09-08 14:12:16][DEBUG] Hyperion Base address: 0x7ffa60fb0000
[2025-09-08 14:12:16][WARN] Attempting to dump IntegrityChecks...
[2025-09-08 14:12:16][INFO] REBASED TO 0x0
[2025-09-08 14:12:16][DEBUG] Dumping Sub-IntegrityChecks...
[2025-09-08 14:12:16][DEBUG] Found 84 results for subChecks!

inline uint64_t subIntegrityChecks[12] = {
    0x4e5271, 0x4e5d41, 0x4f1361,
    0x4f8e11, 0x504c31, 0x5054b1,
    0x506741, 0x506f18, 0x507544,
    0x507928, 0x51b191, 0x521c2d
};
inline uintptr_t generalIntegrityCheck = 0x507544
inline uintptr_t controlFlowGuard = 0x27e9d0
inline uintptr_t whitelistCheckCMP = 0x50903f
inline uintptr_t consoleCheck = 0x65b822
inline uintptr_t icebpCMP = 0xbef9c8



[2025-09-08 14:12:16][INFO] Took 0.141 seconds!
[2025-09-08 14:12:16][INFO] Made by Volxphy
```
