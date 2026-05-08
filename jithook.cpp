#include <Windows.h>
#include <cstdint>
#include <stdio.h>

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

bool WriteDetour32(void* target, void* hook, uint8_t* savedBytes) {
    DWORD old;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old))
        return false;
    memcpy(savedBytes, target, 5);
    uint8_t* t = (uint8_t*)target;
    t[0] = 0xE9;
    *(int32_t*)(t + 1) = (int32_t)((uint8_t*)hook - t - 5);
    VirtualProtect(target, 5, old, &old);
    return true;
}

int __stdcall hk_compileMethod(
    void* thisptr, void* comp, CORINFO_METHOD_INFO* info,
    unsigned flags, uint8_t** nativeEntry, uint32_t* nativeSizeOfCode)
{
    int ret = 0;

    __try {
        ret = orig_compileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (g_log) {
            fprintf(g_log, "EXCEPTION in orig_compileMethod\n");
            fflush(g_log);
        }
        return -1;
    }

    __try {
        if (g_log && info && info->ILCode && info->ILCodeSize > 0) {
            fprintf(g_log, "METHOD 0x%p SIZE %u\n", info->ftn, info->ILCodeSize);
            fwrite(info->ILCode, 1, info->ILCodeSize, g_log);
            fprintf(g_log, "\n---\n");
            fflush(g_log);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (g_log) {
            fprintf(g_log, "EXCEPTION reading IL\n");
            fflush(g_log);
        }
    }

    return ret;
}

void DoHook() {
    g_log = fopen("C:\\Users\\murat\\Desktop\\msil_dump.bin", "wb");
    if (!g_log) return;

    HMODULE hJit = nullptr;
    int tries = 0;
    while (!hJit && tries++ < 200) {
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

    fprintf(g_log, "clrjit base  : %p\n", hJit);
    fprintf(g_log, "pJit         : %p\n", pJit);
    fprintf(g_log, "compileMethod: %p\n", compileMethodPtr);
    fprintf(g_log, "savedBytes before detour: %02X %02X %02X %02X %02X\n",
        ((uint8_t*)compileMethodPtr)[0],
        ((uint8_t*)compileMethodPtr)[1],
        ((uint8_t*)compileMethodPtr)[2],
        ((uint8_t*)compileMethodPtr)[3],
        ((uint8_t*)compileMethodPtr)[4]);
    fflush(g_log);

    // Trampolin: 5 saved byte + JMP geri
    uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, 32,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        fprintf(g_log, "VirtualAlloc failed\n");
        fflush(g_log);
        return;
    }

    uint8_t savedBytes[5];
    if (!WriteDetour32(compileMethodPtr, (void*)hk_compileMethod, savedBytes)) {
        fprintf(g_log, "WriteDetour32 failed\n");
        fflush(g_log);
        VirtualFree(tramp, 0, MEM_RELEASE);
        return;
    }

    // Trampolin yaz: saved 5 byte + JMP compileMethodPtr+5
    memcpy(tramp, savedBytes, 5);
    tramp[5] = 0xE9;
    *(int32_t*)(tramp + 6) = (int32_t)(
        (uint8_t*)compileMethodPtr + 5 - (tramp + 10)
    );

    orig_compileMethod = (compileMethod_t)tramp;

    fprintf(g_log, "Hook installed OK\n");
    fflush(g_log);
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, [](void*) -> DWORD {
            Sleep(1000);
            DoHook();
            return 0;
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}
