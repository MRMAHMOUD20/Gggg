#include <list>
#include <vector>
#include <string>
#include <pthread.h>
#include <thread>
#include <cstring>
#include <jni.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <dlfcn.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <cstddef>
#include <cstdint>
// ============================ CONSTANTS ============================
uintptr_t NewBase = 0, libanogsBase = 0, libUE4Base = 0, libanogsAlloc = 0, libUE4Alloc = 0;
unsigned int libanogsSize = 0x51CCBC;
#define libanogs "libanogs.so"
#define LibUE4 "libUE4.so"
#define BYTE uint8_t
#define WORD uint16_t
#define DWORD uint32_t
#define QWORD uint64_t
#define _BYTE  uint8_t
#define _WORD  uint16_t
#define _DWORD uint32_t
#define _QWORD uint64_t
#define PKG_GL "com.tencent.ig"
#define PKG_VNG "com.vng.pubgmobile"
#define PKG_KR "com.pubg.krmobile"
#define PKG_TW "com.rekoo.pubgm"
#define PKG_IN "com.pubg.imobile"
// ============================ MACROS ============================
#define MTR(RET, NAME, ARGS) \
  RET(*o##NAME) ARGS; \
  RET h##NAME ARGS

#define TSS(RET, NAME, ARGS) \
  RET(*o##NAME) ARGS; \
  RET h##NAME ARGS


#define MTR_ZERO(RET, NAME, ARGS) \
    RET(*o##NAME)               \
    ARGS;                       \
    RET h##NAME ARGS            \
    {                           \
    asm volatile( \
    "mov r0, #0\n"  \
    ); \
} 
// ============================ HOOKING DEFINE ============================
// ============================ Helper Functions ============================
bool isAPKRunning(const char* packageName) {
DIR* dir = opendir("/proc/");
if (!dir) return false;
struct dirent* ptr;
char filepath[50], filetext[128];
while ((ptr = readdir(dir)) != nullptr) {
if (ptr->d_type != DT_DIR) continue;
snprintf(filepath, sizeof(filepath), "/proc/%s/cmdline", ptr->d_name);
FILE* fp = fopen(filepath, "r");
if (fp) {
fgets(filetext, sizeof(filetext), fp);
fclose(fp);
if (strcmp(filetext, packageName) == 0) {
closedir(dir);
return true;}}}
closedir(dir);
return false;}

const char* GetPackageName() {
if (isAPKRunning(PKG_GL)) return PKG_GL;
if (isAPKRunning(PKG_VNG)) return PKG_VNG;
if (isAPKRunning(PKG_KR)) return PKG_KR;
if (isAPKRunning(PKG_TW)) return PKG_TW;
if (isAPKRunning(PKG_IN)) return PKG_IN;
return "unknown pkg";}

bool checkFileForPlugin() {
std::ifstream file("/proc/self/cmdline");
std::string line;
while (file.is_open() && std::getline(file, line)) {
if (line.find(":plugin") != std::string::npos) {
file.close();
kill(getpid(), SIGSTOP);
pthread_exit(NULL);
return true;}}
return false;}
// ============================ HOOKS IMPLEMENTATIONS ============================
// ========== Macro Hooks ==========
#define DumpByCryzer(RET, NAME, ARGS) \
    RET(*o##NAME) ARGS;               \
    RET h##NAME ARGS

void CryzerPatch(const char* libName, uintptr_t address, const std::string& patchBytes) {
    MemoryPatch::createWithHex(libName, address, patchBytes.c_str()).Modify();
}

// ========== Hooked Functions ==========

__int64 (*osub_1DD8B4)(__int64, unsigned char*, size_t);
__int64 hsub_1DD8B4(__int64 vTableAddress, unsigned char* CharPtr, size_t SizeOfCharPtr) {
    if (SizeOfCharPtr == 0x4e) {
        return osub_1DD8B4(vTableAddress, CharPtr, SizeOfCharPtr);
    }
    return 0LL;
}

DumpByCryzer(__int64_t, C16, (__int64_t a1, const char* a2, __int64_t a3)) {
    if (strstr(a2, oxorany("crash")) ||
        strstr(a2, oxorany("opcode")) ||
        strstr(a2, oxorany("scanner")) ||
        strstr(a2, oxorany("hook")) ||
        strstr(a2, oxorany("zygisk")) ||
        strstr(a2, oxorany("Scan_trap")) ||
        strstr(a2, oxorany("blur_exit"))) {
        return 0LL;
    }
    return oC16(a1, a2, a3);
}

DumpByCryzer(__int64, sub_265C1C, (__int64 a1, int a2)) {
    LOGI(oxorany("sub_265C"));
    return 0LL;
}

__int64 (*osub_4DC750)(_BYTE*, char, const char*, ...);
__int64 hsub_4DC750(_BYTE* a1, char a2, const char* a3, ...) {
    LOGI(oxorany("Report Blocked."));
    return -1;
}

__int64 (*osub_1EB978)(__int64, const char*);
__int64 hsub_1EB978(__int64 a1, const char* a2) {
    static const char* const blockList[]{
        oxorany("report_apk"),
        oxorany("scan"),
        oxorany("http"),
        oxorany("mem"),
        oxorany("user"),
        oxorany("malloc"),
        oxorany("MrpcsActiveSig")
    };
    for (const char* needle : blockList) {
        if (strstr(a2, needle) != nullptr)
            return 0;
    }
    return osub_1EB978(a1, a2);
}
__int64_t __fastcall (*osub_DumpByCryzer)(__int64_t *a1);
__int64_t __fastcall hsub_DumpByCryzer(__int64_t *a1)
 {
return 0LL;
    }
/*
__int64 (*osub_1EB978)(__int64 a1, const char *a2);
__int64 __fastcall hsub_1EB978(__int64 a1, const char *a2) {
if (
        // strstr(a2, OBFUSCATE("mrpcs1")) != NULL || 
        strstr(a2, OBFUSCATE("sc_report")) != NULL ||
        // strstr(a2, OBFUSCATE("shedule")) != NULL ||
        strstr(a2, OBFUSCATE("report_apk")) != NULL ||
        strstr(a2, OBFUSCATE("anoscan")) != NULL ||
        strstr(a2, OBFUSCATE("scan")) != NULL ||
        strstr(a2, OBFUSCATE("http")) != NULL ||
        strstr(a2, OBFUSCATE("mem")) != NULL ||
        strstr(a2, OBFUSCATE("user")) != NULL ||
        strstr(a2, OBFUSCATE("local_cache")) != NULL ||
        strstr(a2, OBFUSCATE("cache")) != NULL ||
        strstr(a2, OBFUSCATE("malloc")) != NULL ||
        strstr(a2, OBFUSCATE("ace_worker")) != NULL ||
        strstr(a2, OBFUSCATE("gp")) != NULL ||
        strstr(a2, OBFUSCATE("user")) != NULL ||
        strstr(a2, OBFUSCATE("game_host")) != NULL ||
        strstr(a2, OBFUSCATE("rcv_by_thread")) != NULL ||
        strstr(a2, OBFUSCATE("MrpcsActiveSig")) != NULL ||
        strstr(a2, OBFUSCATE("mem_trap2")) != NULL
    //    strstr(a2, OBFUSCATE("mrpcs_lib")) != NULL
    ) {
    return 0;
    }
return osub_1EB978(a1,a2);
}*/
TSS(__int64, sub_2A3FE4, (__int64 result, __int64 a2)) {
if ( a2 ) {
*(QWORD**)(result + 8) = 0LL;
}
return osub_2A3FE4(result, a2);
}
// ========== Main Thread ==========

void* MAIN_THREAD(void*) {
    std::string package = GetPackageName();
    LOGI(oxorany("Detected Package: %s"), package.c_str());

    // Hook libanogs.so
    while (!isLibraryLoaded(oxorany("libanogs.so"))) sleep(1);

PATCH_LIB("libanogs.so", "0x1391E0", "00 00 80 D2 C0 03 5F D6");//gettimeofday
PATCH_LIB("libanogs.so", "0x3997C8", "00 00 80 D2 C0 03 5F D6");//Fix Offline
HOOK_LIB("libanogs.so", "0x2A3FE4", hsub_2A3FE4, osub_2A3FE4);
  /*  // Patch memory
    std::map<uintptr_t, std::string> patchess = {
        {0x3997C8, "00 00 80 D2 C0 03 5F D6"}, // Fix 10y offline
        {0x3E2FB0, "C0 03 5F D6"},
    };
    for (const auto& patch : patchess) {
        CryzerPatch("libanogs.so", patch.first, patch.second);
    }*/
    // Hook libUE4.so
    while (!isLibraryLoaded(oxorany("libUE4.so"))) sleep(1);
PATCH_LIB("libUE4.so", "0x688f2c8", "00 00 80 D2 C0 03 5F D6");//GrayVerify
PATCH_LIB("libUE4.so", "0x69c4fcc", "00 00 80 D2 C0 03 5F D6");//OnCharacterWeaponShootHit
PATCH_LIB("libUE4.so", "0x6aacc9c", "00 00 80 D2 C0 03 5F D6");//GetBulletHitInfoUploadDataSpesific
PATCH_LIB("libUE4.so", "0x6d0bd90", "00 00 80 D2 C0 03 5F D6");//ShootCharacterVertify
PATCH_LIB("libUE4.so", "0x7688d54", "00 00 80 D2 C0 03 5F D6");//RPC_ServerGlueHiaPark
PATCH_LIB("libUE4.so", "0x7688c18", "00 00 80 D2 C0 03 5F D6");//RPC_ServerCapbo
PATCH_LIB("libUE4.so", "0x768909c", "00 00 80 D2 C0 03 5F D6");//ServerPoPo
PATCH_LIB("libUE4.so", "0x5A92D14", "00 00 80 D2 C0 03 5F D6");//flush Mrpcs

    LOGI(oxorany("Done..."));
    return nullptr;
}

// ========== Library Entry Point ==========

extern "C" __attribute__((constructor)) void lib_main() {
    if (!checkFileForPlugin()) {
        pthread_t thread;
        pthread_create(&thread, nullptr, MAIN_THREAD, nullptr);
        LOGI(oxorany("Main thread created successfully.\n"));
    }
}


//dumped by -- @EG2032
//https://t.me/+MffouX3We-gzMGZk
