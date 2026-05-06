#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <intrin.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ---------------- Anti Debug Checks ----------------

static int adb_check_peb_debug(void) {
    PPEB peb = (PPEB)__readfsdword(0x30);
    if (!peb) return 0;
    if (peb->BeingDebugged) return 1;
    if (peb->NtGlobalFlag & 0x70) return 1;
    PVOID heap = peb->ProcessHeap;
    if (heap) {
        DWORD flags = *(PDWORD)((PBYTE)heap + 0x18);
        if (flags & 0x00200000) return 1;
    }
    return 0;
}

static int adb_check_isdebuggerpresent(void) {
    return IsDebuggerPresent() ? 1 : 0;
}

static int adb_check_remotedebugger(void) {
    BOOL present = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present)) {
        return present ? 1 : 0;
    }
    return 0;
}

static int adb_check_timing(void) {
    unsigned int aux;
    uint64_t start = __rdtscp(&aux);
    volatile int x = 0;
    for (int i = 0; i < 10000; ++i) x += i;
    uint64_t end = __rdtscp(&aux);
    uint64_t diff = end - start;
    // thresholds kept from original; adjust if needed per CPU
    if (diff > 500000 || diff < 1000) return 1;
    return 0;
}

static int adb_check_seh(void) {
    __try {
        __asm { int 0x2d }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // If exception handler runs, assume normal environment
        return 0;
    }
    // If no exception occurred, suspicious (original logic)
    return 1;
}

// Runner that executes all anti-debug checks and returns 1 if any detect debugging
static int run_anti_debug_checks(void) {
    typedef int (*adb_fn)(void);
    adb_fn checks[] = {
        adb_check_peb_debug,
        adb_check_isdebuggerpresent,
        adb_check_remotedebugger,
        adb_check_timing,
        adb_check_seh
    };
    const size_t n = sizeof(checks) / sizeof(checks[0]);
    for (size_t i = 0; i < n; ++i) {
        if (checks[i]()) return 1;
    }
    return 0;
}

// ---------------- System Fingerprint and Password Generation ----------------

static void get_system_fingerprint(char *output, int max_len) {
    if (!output || max_len <= 1) return;

    char comp_name[256] = {0};
    DWORD comp_len = sizeof(comp_name);
    GetComputerNameA(comp_name, &comp_len);

    char win_dir[256] = {0};
    GetWindowsDirectoryA(win_dir, sizeof(win_dir));

    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);

    int cpu_info[4] = {0};
    __cpuid(cpu_info, 1);

    const char *secret_parts[] = {
        "X9kL", "2mQp", "7vRt", "4wYs",
        "1nZb", "8cDf", "3gHj", "6lKm"
    };

    char combined[512];
    int written = _snprintf_s(combined, sizeof(combined), _TRUNCATE,
                              "%s|%s|%u|%d|%s%s",
                              comp_name, win_dir, serial, cpu_info[0],
                              secret_parts[3], secret_parts[7]);

    // Fallback if snprintf fails
    if (written < 0) combined[0] = '\0';

    // SHA-256 via CryptoAPI
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    uint8_t hash[32];
    DWORD hash_len = sizeof(hash);

    BOOL ok = CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (ok) {
        ok = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    }
    if (ok) {
        ok = CryptHashData(hHash, (BYTE*)combined, (DWORD)strlen(combined), 0);
    }
    if (ok) {
        ok = CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0);
    }

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int charset_len = (int)(sizeof(charset) - 1);

    // If hashing failed, fall back to a deterministic but weaker method
    if (!ok) {
        // Simple fallback: mix some bytes from combined
        for (int i = 0; i < 32 && i < max_len - 1; ++i) {
            uint8_t b = (uint8_t)combined[i % (strlen(combined) ? strlen(combined) : 1)];
            output[i] = charset[b % charset_len];
        }
        output[32] = '\0';
    } else {
        for (int i = 0; i < 32 && i < max_len - 1; ++i) {
            output[i] = charset[hash[i] % charset_len];
        }
        output[32] = '\0';
    }

    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

    SecureZeroMemory(combined, sizeof(combined));
    SecureZeroMemory(hash, sizeof(hash));
}

// Constant time comparison
static int constant_time_compare(const char *a, const char *b, size_t len) {
    volatile unsigned int diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

// ---------------- Password Verification ----------------

__declspec(noinline) int verify_password(const char *user_pass) {
    if (!user_pass) return 0;

    // Run anti-debug checks first
    if (run_anti_debug_checks()) return 0;

    char correct[33] = {0};
    get_system_fingerprint(correct, sizeof(correct));

    size_t correct_len = strnlen(correct, sizeof(correct));
    size_t user_len = strnlen(user_pass, 256);

    if (user_len != correct_len) {
        SecureZeroMemory(correct, sizeof(correct));
        return 0;
    }

    int ok = constant_time_compare(user_pass, correct, correct_len);

    SecureZeroMemory(correct, sizeof(correct));
    return ok;
}
