#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <signal.h>
#endif

// ============ 1. SECCOMP (SYSTEM CALL FILTER) ============
// Tüm debugging syscall'larını engelle

void enable_seccomp() {
#ifdef __linux__
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    
    // Sadece izin verilen syscall'lar
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
    
    // BLOCK ptrace, process_vm_readv, etc.
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_readv), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(process_vm_writev), 0);
    
    seccomp_load(ctx);
#endif
}

// ============ 2. INTEL CET / CFI (Control Flow Integrity) ============
// Shadow stack ile return-oriented programming engelle

__attribute__((naked))
void enable_cet() {
    __asm__ volatile (
        "mov $0x10, %%eax\n"    // ARCH_CET
        "mov $0x1, %%ebx\n"     // CET_ENABLE
        "mov $0x0, %%ecx\n"
        "mov $0x0, %%edx\n"
        "syscall\n"
        ::: "eax", "ebx", "ecx", "edx"
    );
}

// ============ 3. TIMING-SENSITIVE VALIDATION ============
// Herhangi bir breakpoint veya single-step anında tespit

volatile uint64_t g_start_cycles;
volatile uint64_t g_verify_cycles;

__attribute__((noinline))
uint64_t rdtsc() {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void start_timing() {
    g_start_cycles = rdtsc();
}

int end_timing() {
    g_verify_cycles = rdtsc() - g_start_cycles;
    
    // Eğer cycle count çok yüksekse (debugger yavaşlatır)
    // veya çok düşükse (emulator)
    if(g_verify_cycles > 1000000 || g_verify_cycles < 1000) {
        return 0;  // Anomaly detected
    }
    return 1;
}

// ============ 4. CACHE-TIMING ATTACK DETECTION ============
// CPU cache state kontrolü (debugger cache polution)

int check_cache_state() {
    volatile char *addr = malloc(4096);
    volatile int time1, time2;
    
    // Measure access time
    uint64_t t1 = rdtsc();
    volatile char x = *addr;
    uint64_t t2 = rdtsc();
    
    free((void*)addr);
    
    // Debugger pollutes L1 cache
    return (t2 - t1) < 200;
}

// ============ 5. TRANSACTIONAL MEMORY (TSX) ============
// Hardware Transactional Memory ile anti-debug

int tsx_protected_verify(const char *pass) {
    uint32_t status;
    
    __asm__ volatile(".byte 0xC7,0xF8 ; xbegin 1f ; xor %0, %0 ; jmp 2f ; 1: mov $1, %0 ; 2:" 
                     : "=r"(status));
    
    if(status == 0) {
        // Transaction succeeded - normal execution
        return normal_verify(pass);
    } else {
        // Transaction aborted - debugger detected
        return 0;
    }
}

// ============ 6. MPX (Memory Protection Extensions) ============
// Bound violation = debugging attempt

void setup_mpx() {
    struct __bound {
        uint64_t lower, upper;
    } bounds;
    
    bounds.lower = (uint64_t)verify_password;
    bounds.upper = (uint64_t)verify_password + 0x1000;
    
    __asm__ volatile("bndmk (%0), %%bnd0" : : "r"(&bounds));
}

// ============ 7. INTEL PT (Processor Trace) DETECTION ============
// Branch trace detection

int check_intel_pt() {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0x14));
    
    // Check if Intel PT is enabled
    return (ecx & 0x1) == 0;  // Enabled = debugger using it
}

// ============ 8. HYPERVISOR DETECTION (SGX) ============
// SGX enclave ile koruma

__attribute__((target("sgx")))
void sgx_protected_code() {
    // Code inside SGX enclave - debugger göremez
    __asm__ volatile("enclu");
}

// ============ 9. KERNEL MODULE INTERACTION ============
// Custom kernel module ile ring0 protection

void check_kernel_module() {
    FILE *fp = fopen("/proc/modules", "r");
    char line[256];
    
    while(fgets(line, sizeof(line), fp)) {
        if(strstr(line, "crackme_protect")) {
            // Module loaded - can bypass
            fclose(fp);
            return;
        }
    }
    fclose(fp);
    
    // Module not loaded - someone is debugging
    exit(1);
}

// ============ 10. NUMA AWARE TIMING ============
// Cross-CPU timing attacks

int numa_timing_check() {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    uint64_t t1 = rdtsc();
    volatile int x = 0;
    for(int i = 0; i < 1000; i++) x++;
    uint64_t t2 = rdtsc();
    
    // Pin to another CPU
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    // If time differs significantly, debugger is injecting
    return (t2 - t1) < 10000;
}

// ============ 11. MEMORY ENCRYPTION (SGX-like) ============
// Runtime memory encryption

void encrypt_memory(uint8_t *data, size_t len, uint64_t key) {
    for(size_t i = 0; i < len; i += 8) {
        uint64_t *block = (uint64_t*)(data + i);
        *block ^= key;
        *block = (*block << 3) | (*block >> 61);
        key = *block;
    }
}

// ============ 12. SELF-VIRTUALIZING CODE ============
// Code that virtualizes itself at runtime

typedef struct {
    uint8_t *bytecode;
    size_t len;
    uint8_t *handler;
} VirtualMachine;

void virtualize_function(void *func, size_t size) {
    VirtualMachine vm;
    
    // Convert function to bytecode
    vm.bytecode = malloc(size);
    memcpy(vm.bytecode, func, size);
    
    // Encrypt bytecode
    for(size_t i = 0; i < size; i++) {
        vm.bytecode[i] ^= 0xAA;
        vm.bytecode[i] = (vm.bytecode[i] << 1) | (vm.bytecode[i] >> 7);
    }
    
    // Execute via interpreter
    vm.handler = malloc(0x1000);
    // Generate interpreter dynamically
}

// ============ 13. RANDOMIZED STACK FRAMES ============
// Her çağrıda farklı stack layout

__attribute__((noinline))
void randomize_stack() {
    volatile char *sp = (volatile char*)__builtin_frame_address(0);
    volatile size_t offset = rand() % 256;
    
    for(size_t i = 0; i < offset; i++) {
        sp[i] ^= 0xAA;
    }
}

// ============ 14. TRAP FLAG DETECTION ============
// Detect single-stepping

int check_trap_flag() {
    uint32_t eflags;
    __asm__ volatile("pushf; pop %0" : "=r"(eflags));
    return (eflags & 0x100) != 0;  // TF bit set
}

// ============ 15. INT3 SCANNING ============
// Scan entire code section for breakpoints

void scan_breakpoints() {
    extern char __executable_start, __etext;
    uint8_t *start = (uint8_t*)&__executable_start;
    uint8_t *end = (uint8_t*)&__etext;
    
    for(uint8_t *p = start; p < end; p++) {
        if(*p == 0xCC) {  // INT3
            // Fix the breakpoint
            uint8_t original = *p;
            *p = 0x90;  // NOP it
            exit(1);    // But exit anyway
        }
    }
}

// ============ MAIN CRACKME ============

int main() {
    // Initialize all protections
    enable_seccomp();           // Kill ptrace/syscall debug
    enable_cet();               // Control flow integrity
    setup_mpx();                // Memory bounds protection
    
    // Anti-debug checks
    start_timing();
    
    if(!end_timing() || !check_cache_state() || !numa_timing_check()) {
        printf("[!] Timing anomaly detected\n");
        return 1;
    }
    
    if(!tsx_protected_verify("dummy") || check_trap_flag()) {
        printf("[!] Debugger detected via TSX/TF\n");
        return 1;
    }
    
    if(check_intel_pt()) {
        printf("[!] Intel PT tracing detected\n");
        return 1;
    }
    
    scan_breakpoints();
    check_kernel_module();
    
    // Real password verification
    char password[256];
    printf("Enter password: ");
    fgets(password, 256, stdin);
    password[strcspn(password, "\n")] = 0;
    
    // Verify with protected environment
    int result = 0;
    
    #pragma omp parallel num_threads(2)
    {
        // Thread 0 = verify, Thread 1 = monitor
        if(omp_get_thread_num() == 0) {
            result = verify_password_protected(password);
        } else {
            // Monitor thread checks for tampering
            volatile int integrity = 1;
            uint64_t last_time = rdtsc();
            
            while(!omp_get_thread_num()) {
                uint64_t now = rdtsc();
                if(now - last_time > 10000) {
                    integrity = 0;  // Too slow - debugger
                }
                last_time = now;
            }
            
            if(!integrity) result = 0;
        }
    }
    
    if(result) {
        printf("✓ Correct!\n");
    } else {
        printf("✗ Wrong!\n");
    }
    
    return 0;
}
