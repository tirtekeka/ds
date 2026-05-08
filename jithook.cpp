#include <Windows.h>
#include <cstdint>
#include <stdio.h>

// MinHook yerine manuel detour — dependency yok
struct CORINFO_METHOD_INFO {
    void*    ftn;
    void*    scope;
    uint8_t* ILCode;
    uint32_t ILCodeSize;
    uint32_t maxStack;
    uint32_t EHcount;
    uint32_t options;
};

typedef int(__stdcall* compileMethod_t)(
    void*, void*, CORINFO_METHOD_INFO*, unsigned, uint8_t**, uint32_t*);

compileMethod_t orig_compileMethod = nullptr;
FILE* g_log = nullptr;

// Trampoline için 16 byte'lık cave
uint8_t g_trampoline[32];

int __stdcall hk_compileMethod(
    void* thisptr, void* comp, CORINFO_METHOD_INFO* info,
    unsigned flags, uint8_t** nativeEntry, uint32_t* nativeSizeOfCode)
{
    int ret = orig_compileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);
    if (g_log && info && info->ILCode && info->ILCodeSize > 0) {
        fprintf(g_log, "METHOD 0x%p SIZE %u\n", info->ftn, info->ILCodeSize);
        fwrite(info->ILCode, 1, info->ILCodeSize, g_log);
        fprintf(g_log, "\n---\n");
        fflush(g_log);
    }
    return ret;
}

bool WriteDetour64(void* target, void* hook, uint8_t* savedBytes) {
    // abs jmp: FF 25 00000000 [8 byte addr] = 14 bytes
    uint8_t patch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP QWORD PTR [RIP+0]
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 // addr
    };
    *(uint64_t*)(patch + 6) = (uint64_t)hook;

    DWORD old;
    if (!VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old))
        return false;

    memcpy(savedBytes, target, 14); // orijinal byte'ları sakla
    memcpy(target, patch, 14);

    VirtualProtect(target, 14, old, &old);
    return true;
}

void DoHook() {
    g_log = fopen("C:\\Users\\murat\\Desktop\\msil_dump.bin", "wb");
    if (!g_log) return;

    HMODULE hJit = nullptr;
    int tries = 0;
    while (!hJit && tries++ < 100) {
        hJit = GetModuleHandleA("clrjit.dll");
        Sleep(100);
    }
    if (!hJit) {
        fprintf(g_log, "clrjit not found\n");
        fflush(g_log);
        return;
    }

    auto getJit = (void*(*)())GetProcAddress(hJit, "getJit");
    if (!getJit) {
        fprintf(g_log, "getJit not found\n");
        fflush(g_log);
        return;
    }

    void* pJit = getJit();
    if (!pJit) {
        fprintf(g_log, "pJit null\n");
        fflush(g_log);
        return;
    }

    void** vtable = *(void***)pJit;
    void* compileMethodPtr = vtable[0];

    fprintf(g_log, "clrjit base: %p\n", hJit);
    fprintf(g_log, "pJit: %p\n", pJit);
    fprintf(g_log, "compileMethod: %p\n", compileMethodPtr);
    fflush(g_log);

    // Trampoline alloc — target'a yakın (±2GB) olması gerekmiyor çünkü abs jmp kullanıyoruz
    uint8_t savedBytes[14];
    
    // orig için trampoline yap: saved bytes + jmp back
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 64,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) return;

    // İlk 14 byte = orijinal instruction'lar (detour sonrası doldurulacak)
    // Son 14 byte = jmp back to target+14
    uint8_t jmpBack[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    *(uint64_t*)(jmpBack + 6) = (uint64_t)compileMethodPtr + 14;

    // vtable'ı OKUMA — yazmıyoruz
    orig_compileMethod = (compileMethod_t)tramp;

    if (!WriteDetour64(compileMethodPtr, (void*)hk_compileMethod, savedBytes)) {
        fprintf(g_log, "WriteDetour64 failed\n");
        fflush(g_log);
        return;
    }

    // Trampoline'i şimdi doldur
    memcpy(tramp, savedBytes, 14);
    memcpy(tramp + 14, jmpBack, 14);

    fprintf(g_log, "Hook installed OK\n");
    fflush(g_log);
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, [](void*) -> DWORD {
            Sleep(1000); // clr init için bekle
            DoHook();
            return 0;
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}
