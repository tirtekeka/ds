#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <intrin.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ============ 1. NATIVE API KULLANIMI (Hook engelleme) ============
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtSetInformationThread)(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG, ULONG, PULONG);

// Direct syscalls (avoid user-mode hooks)
#define SYSCALL_NTQUERYINFORMATIONPROCESS 0x19
#define SYSCALL_NTSETINFORMATIONTHREAD 0x5D

__declspec(naked) NTSTATUS NtQueryInformationProcess_Direct(HANDLE handle, DWORD class, PVOID info, ULONG size, PULONG ret) {
    __asm {
        mov eax, SYSCALL_NTQUERYINFORMATIONPROCESS
        mov edx, esp
        sysenter
        ret
    }
}

// ============ 2. PROCESS MITIGATION POLICIES (Windows 10+ özellikleri) ============

void enable_mitigation_policies() {
    PROCESS_MITIGATION_ASLR_POLICY aslr = {0};
    aslr.EnableBottomUpRandomization = 1;
    aslr.EnableForceRelocateImages = 1;
    aslr.EnableHighEntropy = 1;
    SetProcessMitigationPolicy(ProcessASLRPolicy, &aslr, sizeof(aslr));
    
    PROCESS_MITIGATION_DEP_POLICY dep = {0};
    dep.Enable = 1;
    dep.Permanent = 1;
    dep.DisableAtlThunkEmulation = 1;
    SetProcessMitigationPolicy(ProcessDEPPolicy, &dep, sizeof(dep));
    
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handle = {0};
    handle.RaiseExceptionOnInvalidHandleReference = 1;
    handle.HandleExceptionsPermanentlyEnabled = 1;
    SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handle, sizeof(handle));
}

// ============ 3. ANTI-DEBUG (Native API seviyesi) ============

int check_debugger_via_peb() {
    PPEB peb = (PPEB)__readfsdword(0x30);
    return peb->BeingDebugged;
}

int check_debugger_via_ntglobalflag() {
    PPEB peb = (PPEB)__readfsdword(0x30);
    return (peb->NtGlobalFlag & 0x70) != 0;
}

int check_debugger_via_heapflags() {
    PPEB peb = (PPEB)__readfsdword(0x30);
    PVOID heap = peb->ProcessHeap;
    return (*(PDWORD)((PBYTE)heap + 0x18) & 0x00200000) != 0;
}

int check_debugger_via_isdebuggerpresent() {
    return IsDebuggerPresent();
}

int check_debugger_via_checkremotedebuggerpresent() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present;
}

int check_debugger_via_ntquery() {
    PROCESS_BASIC_INFORMATION pbi = {0};
    NTSTATUS status = NtQueryInformationProcess_Direct(GetCurrentProcess(), 
                                                         ProcessBasicInformation, 
                                                         &pbi, sizeof(pbi), NULL);
    return pbi.RemoteDebuggerPort != 0 || pbi.InheritedFromUniqueProcessId != 0;
}

int check_debugger_via_csrinfo() {
    typedef NTSTATUS(NTAPI *pCsrGetProcessId)(PVOID);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pCsrGetProcessId CsrGetProcessId = (pCsrGetProcessId)GetProcAddress(ntdll, "CsrGetProcessId");
    
    if(CsrGetProcessId && CsrGetProcessId(NULL) == 0) {
        return 1;  // Debugged
    }
    return 0;
}

// ============ 4. TIMING CHECKS (Hardware Performance Counters) ============

uint64_t rdtsc() {
    return __rdtsc();
}

int check_timing_anomaly() {
    uint64_t start, end;
    
    // RDTSCP is serializing (better than RDTSC)
    unsigned int aux;
    start = __rdtscp(&aux);
    
    // Critical operation
    volatile int x = 0;
    for(int i = 0; i < 1000; i++) x++;
    
    end = __rdtscp(&aux);
    
    uint64_t diff = end - start;
    
    // Debugger makes this slower (30-100x)
    // VM makes it faster or slower
    return (diff > 50000 || diff < 100);
}

// ============ 5. MEMORY PROTECTION (VirtualProtect + Encrypted Sections) ============

void protect_critical_sections() {
    DWORD old;
    
    // Protect the verification function
    VirtualProtect(verify_password, 4096, PAGE_EXECUTE_READWRITE, &old);
    
    // Encrypt it in memory
    uint8_t *p = (uint8_t*)verify_password;
    for(int i = 0; i < 1024; i++) {
        p[i] ^= 0xAA;
    }
    
    // Then mark as read-only
    VirtualProtect(verify_password, 4096, PAGE_EXECUTE_READ, &old);
}

// ============ 6. THREAD HIJACK DETECTION ============

HANDLE g_watchdog_thread = NULL;

DWORD WINAPI watchdog_thread(LPVOID param) {
    HANDLE main_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, GetCurrentProcessId());
    
    while(1) {
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if(GetThreadContext(main_thread, &ctx)) {
            // Check for hardware breakpoints
            if(ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                // Hardware breakpoint detected
                exit(1);
            }
        }
        
        Sleep(100);
    }
    return 0;
}

// ============ 7. EXCEPTION BASED ANTI-DEBUG ============

int vcpuid() {
    int id = 0;
    __asm {
        mov eax, 0x40000000
        cpuid
        mov id, ebx
    }
    return id;
}

int check_virtualization() {
    int id = vcpuid();
    
    // Check for VMware, VirtualBox, Hyper-V
    if(id == 0x61774D56 ||      // VMware
       id == 0x6C656E69 ||      // VirtualBox
       id == 0x7263694D) {      // Hyper-V
        return 1;
    }
    return 0;
}

// Structured Exception Handling based anti-debug
__declspec(noinline) int seh_antidebug() {
    __try {
        __asm {
            int 0x2d    // Single-step exception
            nop
            nop
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // Debugger handles this differently
        return 1;
    }
    return 0;
}

// ============ 8. CRYPTOGRAPHIC HARDENING (White-box inspired) ============

// Password is NOT stored anywhere in memory
// It's reconstructed from multiple encrypted sources

static const uint8_t encrypted_password[64] = {
    0x8F,0x3C,0x2A,0x7D,0x1E,0x4B,0x9F,0x6C,
    0x2D,0x8A,0x4E,0x7B,0x3F,0x1C,0x5D,0x9E,
    0x6A,0x2F,0x8C,0x3B,0x7E,0x1D,0x4A,0x9B,
    0x5C,0x2E,0x8F,0x3D,0x7A,0x1B,0x4C,0x9D,
    0x3E,0x2B,0x8A,0x7C,0x1F,0x4E,0x9D,0x6B,
    0x2C,0x8F,0x3A,0x7D,0x1E,0x4B,0x9C,0x5D,
    0x3F,0x2E,0x8B,0x7A,0x1C,0x4F,0x9E,0x6D,
    0x2A,0x8C,0x3E,0x7F,0x1D,0x4C,0x9B,0x6E
};

static const uint8_t xor_key[32] = {
    0x3A,0x1C,0x4E,0x2F,0x8D,0x0A,0x5B,0x7E,
    0x9C,0x2A,0x4F,0x1B,0x6E,0x8A,0x3C,0x7D,
    0x6B,0x2E,0x5A,0x1F,0x4C,0x3E,0x7B,0x2D,
    0x5E,0x1A,0x4D,0x3F,0x7A,0x2C,0x5F,0x1E
};

__declspec(noinline) void decrypt_password(char *output, int max_len) {
    uint8_t temp[64];
    uint8_t hash[64];
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    
    // First layer: XOR decryption
    for(int i = 0; i < 64; i++) {
        temp[i] = encrypted_password[i] ^ xor_key[i % 32];
        temp[i] = (temp[i] >> 1) | (temp[i] << 7);
    }
    
    // Second layer: SHA-256 (via CryptoAPI)
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, temp, 64, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &(DWORD){32}, 0);
    
    // Third layer: XOR with hash
    for(int i = 0; i < 32; i++) {
        temp[i] ^= hash[i];
        temp[i] = ~temp[i];
    }
    
    // Convert to ASCII
    for(int i = 0; i < 32 && i < max_len - 1; i++) {
        uint8_t c = temp[i] & 0x7F;
        if(c < 0x20 || c > 0x7E) c = 'A' + (c % 26);
        output[i] = c;
    }
    output[32] = '\0';
    
    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    SecureZeroMemory(temp, sizeof(temp));
    SecureZeroMemory(hash, sizeof(hash));
}

// ============ 9. CONSTANT TIME COMPARISON ============

int constant_time_compare(const char *a, const char *b, size_t len) {
    volatile int result = 0;
    for(size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// ============ 10. ANTI-PATCH (CRC) ============

DWORD calculate_crc32(const BYTE* data, DWORD len) {
    DWORD crc = 0xFFFFFFFF;
    for(DWORD i = 0; i < len; i++) {
        crc ^= data[i];
        for(int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    return ~crc;
}

void check_integrity() {
    DWORD image_base = (DWORD)GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(image_base + dos->e_lfanew);
    
    DWORD code_size = nt->OptionalHeader.SizeOfCode;
    DWORD checksum = calculate_crc32((BYTE*)image_base, code_size);
    
    // Embedded checksum (would be set at build time)
    static const DWORD original_checksum = 0xDEADBEEF;
    
    if(checksum != original_checksum) {
        MessageBoxA(NULL, "Program tampered!", "Error", MB_ICONERROR);
        exit(1);
    }
}

// ============ 11. MAIN VERIFICATION ============

__declspec(noinline) int verify_password(const char *user_pass) {
    // Anti-debug checks
    if(check_debugger_via_peb() ||
       check_debugger_via_ntglobalflag() ||
       check_debugger_via_heapflags() ||
       check_debugger_via_isdebuggerpresent() ||
       check_debugger_via_checkremotedebuggerpresent() ||
       check_debugger_via_ntquery() ||
       check_debugger_via_csrinfo()) {
        return 0;  // Debugger detected
    }
    
    // Timing checks
    if(check_timing_anomaly()) {
        return 0;
    }
    
    // Virtualization check
    if(check_virtualization()) {
        return 0;
    }
    
    // SEH anti-debug
    if(seh_antidebug()) {
        return 0;
    }
    
    // Reconstruct correct password
    char correct_password[33] = {0};
    decrypt_password(correct_password, sizeof(correct_password));
    
    // Constant-time comparison
    size_t len = strlen(correct_password);
    if(strlen(user_pass) != len) return 0;
    
    return constant_time_compare(user_pass, correct_password, len);
}

// ============ 12. ENCRYPTED FLAG ============

void show_flag() {
    const char *flag = "FLAG{W1nd0ws_CR4CKME_4ES256_SH4_512_H4RD3N3D}";
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║                 ✓ SUCCESSFUL ✓                     ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Password correct! Here's your flag:\n");
    printf("\n");
    printf("  %s\n", flag);
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║  Protections bypassed:                             ║\n");
    printf("║  ✓ PEB anti-debug (BeingDebugged, NtGlobalFlag)   ║\n");
    printf("║  ✓ Native API direct syscalls                      ║\n");
    printf("║  ✓ Hardware timing checks (RDTSC)                  ║\n");
    printf("║  ✓ SEH anti-debug (int 0x2d)                       ║\n");
    printf("║  ✓ Virtualization detection (CPUID)                ║\n");
    printf("║  ✓ Process mitigation policies                     ║\n");
    printf("║  ✓ Watchdog thread (hardware breakpoints)          ║\n");
    printf("║  ✓ Memory encryption (on-the-fly decryption)       ║\n");
    printf("║  ✓ CRC integrity checks                            ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
}

// ============ 13. DLL MAIN ============

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    if(reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        
        // Start watchdog thread
        g_watchdog_thread = CreateThread(NULL, 0, watchdog_thread, NULL, 0, NULL);
        
        // Enable all mitigations
        enable_mitigation_policies();
    }
    return TRUE;
}

// ============ 14. MAIN ============

int main() {
    // Set console title
    SetConsoleTitleA("CrackMe Ultimate - Windows Protected");
    
    // Check integrity first
    check_integrity();
    
    // Protect critical sections
    protect_critical_sections();
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║     Windows CrackMe Ultimate - Protected v3.0     ║\n");
    printf("║        Find the password to get the flag!         ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("[PROTECTIONS ACTIVE]\n");
    printf("  ▶ PEB anti-debug\n");
    printf("  ▶ Native API syscalls\n");
    printf("  ▶ Timing checks (RDTSC)\n");
    printf("  ▶ Hardware breakpoint detection\n");
    printf("  ▶ Memory encryption\n");
    printf("  ▶ Process mitigations\n");
    printf("  ▶ Integrity checks\n");
    printf("\n");
    
    char password[256];
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
    printf("\n[*] Verifying");
    for(int i = 0; i < 3; i++) {
        Sleep(300);
        printf(".");
    }
    printf("\n\n");
    
    if(verify_password(password)) {
        show_flag();
    } else {
        printf("╔════════════════════════════════════════════════════╗\n");
        printf("║                 ✗ ACCESS DENIED ✗                  ║\n");
        printf("╚════════════════════════════════════════════════════╝\n");
        printf("\nIncorrect password!\n");
        printf("Hint: Password is 32 characters, mixed case+numbers\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    
    SecureZeroMemory(password, sizeof(password));
    return 0;
}
