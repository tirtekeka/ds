#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib") 
#else
#include <x86intrin.h>
#include <sys/mman.h>
#endif

#include <sodium.h>

// ---------------- Anti-debug helpers ----------------
static int check_isdebuggerpresent(void) {
#ifdef _WIN32
    return IsDebuggerPresent() ? 1 : 0;
#else
    return 0;
#endif
}

static int check_timing(void) {
    unsigned int aux;
    uint64_t start = __rdtscp(&aux);
    volatile int x = 0;
    for (int i = 0; i < 10000; ++i) x += i;
    uint64_t end = __rdtscp(&aux);
    uint64_t diff = end - start;
    if (diff > 500000 || diff < 1000) return 1;
    return 0;
}

static int check_seh(void) {
#ifdef _WIN32
    __try {
        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 1;
#else
    return 0;
#endif
}

static int run_anti_debug_checks(void) {
    if (check_isdebuggerpresent()) return 1;
    if (check_timing()) return 1;
    if (check_seh()) return 1;
    return 0;
}

// ---------------- GÖMÜLÜ PARÇALAR ----------------
static const unsigned char HASH_PART_0[] = { 
    126, 59, 40, 61, 53, 52, 104, 51, 62, 126, 44, 103, 107, 99, 126, 55, 
    103, 108, 111, 111, 105, 108, 118, 46, 103, 104, 118, 42, 103, 107, 
    126, 57, 104, 99, 46, 0, 2, 20, 50, 56, 18, 11, 126, 51, 18, 98, 
    117, 51, 14, 98, 117, 51, 14, 98, 117, 51, 14, 98, 117, 51, 14, 98, 
    117, 51, 14, 98, 117, 51, 14, 98, 117, 51, 14, 98, 117, 51, 14, 98, 
    117, 51, 14, 98, 117, 51, 14, 98 
};

static const size_t HASH_PART_0_LEN = 86;
static const unsigned char HASH_MASK = 0x5a;
static const size_t HASH_PART_COUNT = 1;

static const unsigned char* HASH_PARTS[] = { HASH_PART_0 };
static const size_t HASH_PARTS_LEN[] = { HASH_PART_0_LEN };

static int reconstruct_hash_string(char *out, size_t out_len) {
    if (!out) return 0;
    size_t pos = 0;
    for (size_t i = 0; i < HASH_PART_COUNT; ++i) {
        const unsigned char *p = HASH_PARTS[i];
        size_t plen = HASH_PARTS_LEN[i];
        for (size_t j = 0; j < plen; ++j) {
            unsigned char b = (unsigned char)(p[j] ^ HASH_MASK);
            if (pos + 1 >= out_len) return 0;
            out[pos++] = (char)b;
        }
    }
    out[pos] = '\0';
    return 1;
}

int main(void) {
    if (sodium_init() < 0) return 1;

    if (run_anti_debug_checks()) return 1;

    char hash_str[512];
    if (!reconstruct_hash_string(hash_str, sizeof(hash_str))) return 1;

#ifdef _WIN32
    VirtualLock(hash_str, strlen(hash_str));
#else
    mlock(hash_str, strlen(hash_str));
#endif

    char password[1024];
    printf("Enter password: ");
    if (!fgets(password, sizeof(password), stdin)) goto cleanup;
    password[strcspn(password, "\n")] = 0;

    int ok = 0;
    if (crypto_pwhash_str_verify(hash_str, password, strlen(password)) == 0) {
        ok = 1;
    }

cleanup:
    sodium_memzero(password, sizeof(password));
    sodium_memzero(hash_str, sizeof(hash_str));
#ifdef _WIN32
    VirtualUnlock(hash_str, strlen(hash_str));
#else
    munlock(hash_str, strlen(hash_str));
#endif

    if (ok) {
#ifdef _WIN32
        MessageBoxA(NULL, "ACCESS GRANTED", "Verification", MB_OK | MB_ICONINFORMATION);
#else
        printf("ACCESS GRANTED\n");
#endif
        return 0;
    } else {
        printf("ACCESS DENIED\n");
        return 1;
    }
}
