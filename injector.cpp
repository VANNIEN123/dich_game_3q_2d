#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <string>

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcout << L"Usage: injector.exe <PID> <DLL_PATH>\n";
        return 1;
    }

    DWORD pid = std::wcstoul(argv[1], nullptr, 10);
    std::wstring dllPath = argv[2];

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"Failed to open process. Error: " << GetLastError() << L"\n";
        return 2;
    }

    // Allocate memory in target process for DLL path
    size_t size = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) {
        std::wcout << L"Failed to allocate memory. Error: " << GetLastError() << L"\n";
        CloseHandle(hProcess);
        return 3;
    }

    // Write DLL path to target process memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteBuf, dllPath.c_str(), size, &bytesWritten)) {
        std::wcout << L"Failed to write process memory. Error: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 4;
    }

    // Get address of LoadLibraryW in kernel32.dll
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibrary) {
        std::wcout << L"Failed to get LoadLibraryW address. Error: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 5;
    }

    // Create remote thread in target process
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibrary, pRemoteBuf, 0, nullptr);
    if (!hThread) {
        std::wcout << L"Failed to create remote thread. Error: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 6;
    }

    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Get exit code of thread to check if LoadLibraryW succeeded
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    if (exitCode == 0) {
        std::wcout << L"LoadLibraryW failed inside target process.\n";
        return 7;
    }

    std::wcout << L"Successfully injected DLL!\n";
    return 0;
}
