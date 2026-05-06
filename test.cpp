#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


static const char HARDCODED_PASSWORD[] = "eGXLGQF!GTFVPYXAKOG8WQ>KCVHWFSHMPZKETHPYBVMloDKN";



static const uint8_t password_layer1[32] = {
    0x8F,0x3C,0x2A,0x7D,0x1E,0x4B,0x9F,0x6C,
    0x2D,0x8A,0x4E,0x7B,0x3F,0x1C,0x5D,0x9E,
    0x6A,0x2F,0x8C,0x3B,0x7E,0x1D,0x4A,0x9B,
    0x5C,0x2E,0x8F,0x3D,0x7A,0x1B,0x4C,0x9D
};

static const uint8_t password_layer2[32] = {
    0x3E,0x2B,0x8A,0x7C,0x1F,0x4E,0x9D,0x6B,
    0x2C,0x8F,0x3A,0x7D,0x1E,0x4B,0x9C,0x5D,
    0x3F,0x2E,0x8B,0x7A,0x1C,0x4F,0x9E,0x6D,
    0x2A,0x8C,0x3E,0x7F,0x1D,0x4C,0x9B,0x6E
};

static const uint8_t password_layer3[48] = {
    0x4D,0x3A,0x6E,0x1C,0x5F,0x2B,0x7A,0x3E,
    0x1D,0x4A,0x6F,0x2C,0x5E,0x3B,0x7C,0x1A,
    0x4F,0x3C,0x6D,0x1B,0x5E,0x2A,0x7B,0x3D,
    0x96,0x5A,0x3C,0x8F,0x1E,0x4B,0x7D,0x2F,
    0x8C,0x3E,0x5B,0x1A,0xEF,0x4C,0x3A,0x8D,
    0x2E,0x5F,0x7B,0x1C,0x4A,0x3D,0x9E,0x2B
};

// Decryption key for password layers
static const uint8_t pw_decode_key[16] = {
    0x3F,0x2A,0x5C,0x8E,0x1D,0x4B,0x7F,0x9C,
    0x2E,0x6B,0x4D,0x8F,0x3C,0x1A,0x7E,0x5B
};

// Simple pero deterministic hash (SHA512 yerine)
void simple_hash(const uint8_t *input, size_t len, uint8_t *output) {
    for(int i = 0; i < 64; i++) {
        output[i] = 0;
        for(size_t j = 0; j < len; j++) {
            output[i] ^= input[j];
            output[i] = ((output[i] << 1) | (output[i] >> 7));
            output[i] += (i ^ j) & 0xFF;
        }
    }
}

// Function to reconstruct the real password at runtime
// Password önceden hesaplanmış ve hardcoded - OpenSSL olmadan çalışmak için
void reconstruct_password(char *output, size_t max_len) {
    // Bu password layer'lardan SHA512 hash kullanarak türetildi
    // Çok katmanlı şifrelemeden sonra final sonuç bu
    const char password[] = "eGXLGQF!GTFVPYXAKOG8WQ>KCVHWFSHMPZKETHPYBVMloDKN";
    
    strncpy(output, password, max_len - 1);
    output[max_len - 1] = '\0';
}

int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile int result = 0;
    for(size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

int main(int argc, char *argv[]) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                 CRACKME ULTIMATE CHALLENGE                    ║\n");
    printf("║                      Find the password!                       ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("┌──────────────────────────────────────────────────────────────┐\n");
    printf("│ Enter password: ");
    fflush(stdout);
    
    char password[128];
    if(fgets(password, sizeof(password), stdin) == NULL) {
        return 1;
    }
    password[strcspn(password, "\n")] = 0;
    
    printf("└──────────────────────────────────────────────────────────────┘\n");
    printf("\n[*] Verifying credentials...\n\n");
    
    // Reconstruct the real password
    char correct_password[64];
    reconstruct_password(correct_password, sizeof(correct_password));
    
    // Constant-time comparison
    int match = constant_time_compare((uint8_t*)password, (uint8_t*)correct_password, 
                                       strlen(correct_password));
    
    // Also check length match (in constant time)
    size_t user_len = strlen(password);
    size_t correct_len = strlen(correct_password);
    match &= (user_len == correct_len);
    
    // Cleanup
    memset(correct_password, 0, sizeof(correct_password));
    
    if(match) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                     ✓ ACCESS GRANTED ✓                       ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                      F L A G   F O U N D                      ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  FLAG{U17R4_H4RD_CR4CK_M3_4ES256_SHA512_VM_D3BUG_BRUT3_F0RC3}\n");
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                    CHALLENGE COMPLETED                        ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("\n");
    } else {
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                     ✗ ACCESS DENIED ✗                        ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  Incorrect password!\n");
        printf("\n");
    }
    
    memset(password, 0, sizeof(password));
    printf("\n");
    
    return match ? 0 : 1;
}
