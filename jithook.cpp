// jithook.cpp - inject edilecek DLL
#include <Windows.h>
#include <stdio.h>
#include <cstdint>

// CORINFO_METHOD_INFO partial
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
    void* thisptr,
    void* comp,
    CORINFO_METHOD_INFO* info,
    unsigned flags,
    uint8_t** nativeEntry,
    uint32_t* nativeSizeOfCode
);

compileMethod_t orig_compileMethod = nullptr;
FILE* g_log = nullptr;

int __stdcall hk_compileMethod(
    void* thisptr,
    void* comp,
    CORINFO_METHOD_INFO* info,
    unsigned flags,
    uint8_t** nativeEntry,
    uint32_t* nativeSizeOfCode)
{
    // Önce orijinali çağır — decrypt işlemi burada olur
    int ret = orig_compileMethod(thisptr, comp, info, flags, nativeEntry, nativeSizeOfCode);

    // Decrypt sonrası MSIL'i yaz
    if (g_log && info && info->ILCode && info->ILCodeSize > 0) {
        // token almak için ICorJitInfo->getMethodDefFromMethod
        // basit yaklaşım: pointer'ı token olarak kullan
        fprintf(g_log, "METHOD 0x%p SIZE %u\n", info->ftn, info->ILCodeSize);
        fwrite(info->ILCode, 1, info->ILCodeSize, g_log);
        fprintf(g_log, "\n---\n");
        fflush(g_log);
    }
    return ret;
}

void DoHook() {
    g_log = fopen("C:\\Users\\murat\\Desktop\\msil_dump.bin", "wb");

    // clrjit.dll bul
    HMODULE hJit = nullptr;
    while (!hJit) {
        hJit = GetModuleHandleA("clrjit.dll");
        Sleep(100);
    }

    // getJit export'u bul → ICorJitCompiler* alır
    auto getJit = (void*(*)())GetProcAddress(hJit, "getJit");
    if (!getJit) return;

    void* pJit = getJit();
    if (!pJit) return;

    // vtable[0] = compileMethod
    void** vtable = *(void***)pJit;

    // vtable[0]'ı hook'la
    DWORD old;
    VirtualProtect(&vtable[0], sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
    orig_compileMethod = (compileMethod_t)vtable[0];
    vtable[0] = (void*)hk_compileMethod;
    VirtualProtect(&vtable[0], sizeof(void*), old, &old);
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, [](void*) -> DWORD {
            DoHook();
            return 0;
        }, nullptr, 0, nullptr);
    }
    return TRUE;
}
