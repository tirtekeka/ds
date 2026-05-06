#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <intrin.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// ============ KRİTİK: Şifre BINARY'DE HİÇBİR YERDE YOK! ============
// Şifre runtime'da çağrılan fonksiyonlardan HESAPLANIYOR
// Ne encoded ne de encrypted - tamamen dinamik!

// ============ 1. ANTI-DEBUG (Önceki gibi) ============
int check_peb_debug() {
    PPEB peb = (PPEB)__readfsdword(0x30);
    if(peb->BeingDebugged) return 1;
    if(peb->NtGlobalFlag & 0x70) return 1;
    PVOID heap = peb->ProcessHeap;
    if(*(PDWORD)((PBYTE)heap + 0x18) & 0x00200000) return 1;
    return 0;
}

int check_isdebuggerpresent() { return IsDebuggerPresent(); }

int check_remotedebugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present;
}

int check_timing() {
    uint64_t start, end;
    unsigned int aux;
    start = __rdtscp(&aux);
    volatile int x = 0;
    for(int i = 0; i < 10000; i++) x += i;
    end = __rdtscp(&aux);
    uint64_t diff = end - start;
    return (diff > 500000 || diff < 1000);
}

int check_seh() {
    __try {
        __asm { int 0x2d }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 1;
}

// ============ 2. ŞİFRE OLUŞTURMA (Runtime Computation) ============
// Binary'de HİÇBİR string yok!
// Şifre, sistem bilgilerinden + zaman + rastgele hesaplanır
// Her çalıştırmada SAME password (deterministic)

void get_system_fingerprint(char *output, int max_len) {
    // Get computer name
    char comp_name[256];
    DWORD size = sizeof(comp_name);
    GetComputerNameA(comp_name, &size);
    
    // Get Windows directory
    char win_dir[256];
    GetWindowsDirectoryA(win_dir, sizeof(win_dir));
    
    // Get volume serial number
    DWORD serial;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    
    // Get processor info
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    
    // Çok gizli bir sabit (binary'de var ama tek başına anlamsız)
    const char *secret_parts[] = {
        "X9kL", "2mQp", "7vRt", "4wYs",
        "1nZb", "8cDf", "3gHj", "6lKm"
    };
    
    // Combine everything and hash
    char combined[512];
    snprintf(combined, sizeof(combined), "%s|%s|%d|%d|%s%s",
             comp_name, win_dir, serial, cpu_info[0],
             secret_parts[3], secret_parts[7]);
    
    // SHA-256
    uint8_t hash[32];
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD hash_len = 32;
    
    CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)combined, strlen(combined), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0);
    
    // Hash'i şifreye çevir (A-Z, a-z, 0-9, !@#$%^&*)
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    int charset_len = sizeof(charset) - 1;
    
    for(int i = 0; i < 32 && i < max_len - 1; i++) {
        output[i] = charset[hash[i] % charset_len];
    }
    output[32] = '\0';
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    SecureZeroMemory(combined, sizeof(combined));
    SecureZeroMemory(hash, sizeof(hash));
}

// ============ 3. ŞİFRE DOĞRULAMA (Zero-Knowledge) ============
// Kullanıcının şifresiyle sistem fingerprint'ini karşılaştır
// Ama fingerprint HİÇBİR YERDE SAKLANMAZ!

__declspec(noinline) int verify_password(const char *user_pass) {
    // Anti-debug
    if(check_peb_debug() || check_isdebuggerpresent() || 
       check_remotedebugger() || check_timing() || check_seh()) {
        return 0;
    }
    
    // Generate correct password from system (ON THE FLY)
    char correct[33] = {0};
    get_system_fingerprint(correct, sizeof(correct));
    
    // Compare
    size_t len = strlen(correct);
    if(strlen(user_pass) != len) {
        SecureZeroMemory(correct, sizeof(correct));
        return 0;
    }
    
    volatile int result = 0;
    for(size_t i = 0; i < len; i++) {
        result |= user_pass[i] ^ correct[i];
    }
    
    SecureZeroMemory(correct, sizeof(correct));
    return result == 0;
}

// ============ 4. DEBUG KONTROLÜ İLE FLAG ============
void show_flag() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║                    ✓ ACCESS GRANTED ✓                    ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("Congratulations! You found the correct password!\n");
    printf("\n");
    printf("FLAG: ZERO-KNOWLEDGE-PASSWORD-2025\n");
    printf("\n");
    printf("Note: The password changes per machine!\n");
    printf("It's derived from your system fingerprint.\n");
    printf("\n");
}

// ============ 5. MAIN ============
int main() {
    SetConsoleTitleA("CrackMe - Zero Knowledge Password");
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     ZERO-KNOWLEDGE CRACKME - No Password in Binary!      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("[!] The password is NOT stored anywhere in this binary!\n");
    printf("[!] It is derived from YOUR system fingerprint.\n");
    printf("[!] Each computer has a DIFFERENT password.\n");
    printf("\n");
    
    char password[256];
    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = 0;
    
    if(verify_password(password)) {
        show_flag();
    } else {
        printf("\n✗ Wrong password!\n");
        printf("\nHint: Run this program on your own machine,\n");
        printf("      the password is derived from your:\n");
        printf("      - Computer name\n");
        printf("      - Windows directory path\n");
        printf("      - Volume serial number\n");
        printf("      - CPU info\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}
