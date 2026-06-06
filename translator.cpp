#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

// Global translation cache
std::unordered_map<std::wstring, std::wstring> g_translationCache;
std::mutex g_cacheMutex;

SOCKET g_udpSocket = INVALID_SOCKET;
sockaddr_in g_serverAddr;
std::thread g_receiverThread;
bool g_running = false;

// Thread-Local active translation mapping
thread_local std::string t_activeDummy;
thread_local std::wstring t_activeTranslated;
thread_local int t_lastMatchedOffset = 0;

// Check if string contains Chinese (specifically GBK Chinese, filtering out Vietnamese)
bool IsChineseString(const std::wstring& ws) {
    if (ws.empty()) return false;
    bool hasCJK = false;
    for (wchar_t c : ws) {
        if (c >= 0x4e00 && c <= 0x9fff) {
            hasCJK = true;
        }
        if (c >= 0x1E00 && c <= 0x1EFF) return false;
        if (c == 0x0110 || c == 0x0111) return false; // Đ, đ
        if (c == 0x01A0 || c == 0x01A1) return false; // Ơ, ơ
        if (c == 0x01AF || c == 0x01B0) return false; // Ư, ư
        if (c == L'?') return false;
    }
    return hasCJK;
}


// Request translation over UDP
void RequestTranslation(const std::wstring& chStr) {
    if (g_udpSocket == INVALID_SOCKET) return;
    int byteLen = chStr.size() * sizeof(wchar_t);
    sendto(g_udpSocket, (const char*)chStr.data(), byteLen, 0, (struct sockaddr*)&g_serverAddr, sizeof(g_serverAddr));
}

// Trampoline Hook helper
struct Hook {
    void* target;
    void* trampoline;
    void* hookFunc;
};

void* CreateTrampoline(void* target) {
    BYTE* trampoline = (BYTE*)VirtualAlloc(NULL, 10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampoline) return nullptr;
    memcpy(trampoline, target, 5);
    trampoline[5] = 0xE9; // JMP rel32
    DWORD relativeAddress = ((DWORD)target + 5) - ((DWORD)trampoline + 10);
    memcpy(&trampoline[6], &relativeAddress, 4);
    return trampoline;
}

void InstallHook(Hook& h, void* target, void* hookFunc) {
    h.target = target;
    h.hookFunc = hookFunc;
    h.trampoline = CreateTrampoline(target);
    
    DWORD oldProtect;
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    ((BYTE*)target)[0] = 0xE9; // JMP rel32
    DWORD relativeAddress = (DWORD)hookFunc - ((DWORD)target + 5);
    memcpy((BYTE*)target + 1, &relativeAddress, 4);
    VirtualProtect(target, 5, oldProtect, &oldProtect);
}

void UninstallHook(const Hook& h) {
    if (!h.target || !h.trampoline) return;
    DWORD oldProtect;
    VirtualProtect(h.target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(h.target, h.trampoline, 5);
    VirtualProtect(h.target, 5, oldProtect, &oldProtect);
    VirtualFree(h.trampoline, 0, MEM_RELEASE);
}

// Hook definitions
Hook hookMultiByteToWideChar;
Hook hookCreateFontIndirectW;
Hook hookCreateFontW;
Hook hookExtTextOutW;
Hook hookDrawTextW;
Hook hookRenderText;
Hook hookGetWordIncWidth;

// Typedefs for original function calls
typedef int (WINAPI* MultiByteToWideChar_t)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef HFONT (WINAPI* CreateFontIndirectW_t)(LOGFONTW*);
typedef HFONT (WINAPI* CreateFontW_t)(int, int, int, int, int, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPCWSTR);
typedef BOOL (WINAPI* ExtTextOutW_t)(HDC, int, int, UINT, const RECT*, LPCWSTR, UINT, const int*);
typedef int (WINAPI* DrawTextW_t)(HDC, LPCWSTR, int, LPRECT, UINT);
typedef void (__thiscall* RenderText_t)(void*, const char*, int, int, DWORD, int);
typedef int (__thiscall* GetWordIncWidth_t)(void*, const char*, int);

#define OriginalMultiByteToWideChar ((MultiByteToWideChar_t)hookMultiByteToWideChar.trampoline)
#define OriginalCreateFontIndirectW ((CreateFontIndirectW_t)hookCreateFontIndirectW.trampoline)
#define OriginalCreateFontW ((CreateFontW_t)hookCreateFontW.trampoline)
#define OriginalExtTextOutW ((ExtTextOutW_t)hookExtTextOutW.trampoline)
#define OriginalDrawTextW ((DrawTextW_t)hookDrawTextW.trampoline)
#define OriginalRenderText ((RenderText_t)hookRenderText.trampoline)
#define OriginalGetWordIncWidth ((GetWordIncWidth_t)hookGetWordIncWidth.trampoline)

// Helper to get wide string from ANSI
std::wstring GetWideString(const char* text) {
    int sizeNeeded = OriginalMultiByteToWideChar(936, 0, text, -1, NULL, 0);
    if (sizeNeeded > 0) {
        std::vector<wchar_t> temp(sizeNeeded);
        OriginalMultiByteToWideChar(936, 0, text, -1, temp.data(), sizeNeeded);
        std::wstring ws(temp.data(), sizeNeeded);
        while (!ws.empty() && ws.back() == L'\0') {
            ws.pop_back();
        }
        return ws;
    }
    return L"";
}

// Hooked MultiByteToWideChar
int WINAPI MyMultiByteToWideChar(
    UINT CodePage,
    DWORD dwFlags,
    LPCCH lpMultiByteStr,
    int cbMultiByte,
    LPWSTR lpWideCharStr,
    int cchWideChar
) {
    // 1. Check if we have an active thread-local dummy string mapped
    if (!t_activeDummy.empty() && lpMultiByteStr) {
        int dummyLen = t_activeDummy.length();
        int searchLen = (cbMultiByte > 0) ? cbMultiByte : strlen(lpMultiByteStr);
        if (searchLen > 0 && searchLen <= dummyLen) {
            int matchedOffset = -1;
            
            // Try pointer subtraction first (fast and 100% accurate if no copy)
            const char* dummyStart = t_activeDummy.c_str();
            const char* dummyEnd = dummyStart + dummyLen;
            if (lpMultiByteStr >= dummyStart && lpMultiByteStr < dummyEnd) {
                matchedOffset = lpMultiByteStr - dummyStart;
            }
            
            // Fallback to sequential search from t_lastMatchedOffset
            if (matchedOffset == -1) {
                for (int offset = t_lastMatchedOffset; offset <= dummyLen - searchLen; offset++) {
                    if (memcmp(lpMultiByteStr, t_activeDummy.c_str() + offset, searchLen) == 0) {
                        matchedOffset = offset;
                        break;
                    }
                }
                if (matchedOffset == -1) {
                    for (int offset = 0; offset < t_lastMatchedOffset; offset++) {
                        if (memcmp(lpMultiByteStr, t_activeDummy.c_str() + offset, searchLen) == 0) {
                            matchedOffset = offset;
                            break;
                        }
                    }
                }
            }
            
            if (matchedOffset != -1) {
                t_lastMatchedOffset = matchedOffset + searchLen;
                
                // Match found! Resolve characters using thread-local translated string
                if (searchLen == 1 || cchWideChar == 1) {
                    wchar_t targetChar = t_activeTranslated[matchedOffset];
                    if (cchWideChar == 0) return 1;
                    if (lpWideCharStr) {
                        lpWideCharStr[0] = targetChar;
                        return 1;
                    }
                } else {
                    std::wstring remaining = t_activeTranslated.substr(matchedOffset);
                    int remLen = remaining.length();
                    if (cchWideChar == 0) return remLen;
                    if (lpWideCharStr) {
                        int copyLen = (remLen < cchWideChar) ? remLen : cchWideChar;
                        memcpy(lpWideCharStr, remaining.c_str(), copyLen * sizeof(wchar_t));
                        if (copyLen < cchWideChar) {
                            lpWideCharStr[copyLen] = L'\0';
                        }
                        return copyLen;
                    }
                }
            }
        }
    }

    // 2. Fallback to original conversion
    return OriginalMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
}

// Hooked RenderText from Engine.dll
void __fastcall MyRenderText(void* pThis, void* edx, const char* text, int x, int y, DWORD color, int unknown) {
    if (!text || text[0] == '\0') {
        OriginalRenderText(pThis, text, x, y, color, unknown);
        return;
    }
    
    std::wstring standardWide = GetWideString(text);
    std::wstring vietWStr;
    bool translated = false;
    
    if (IsChineseString(standardWide)) {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_translationCache.find(standardWide);
        if (it != g_translationCache.end()) {
            vietWStr = it->second;
            translated = true;
        } else {
            RequestTranslation(standardWide);
        }
    }
    
    if (translated) {
        // Create dummy ASCII string of the same length
        int len = vietWStr.length();
        std::string dummy(len, 'a');
        for (int i = 0; i < len; i++) {
            dummy[i] = 'a' + (i % 26);
        }
        
        // Backup thread local values (recursion safety)
        std::string backupDummy = t_activeDummy;
        std::wstring backupTranslated = t_activeTranslated;
        
        t_activeDummy = dummy;
        t_activeTranslated = vietWStr;
        t_lastMatchedOffset = 0; // RESET offset tracker
        
        OriginalRenderText(pThis, dummy.c_str(), x, y, color, unknown);
        
        t_activeDummy = backupDummy;
        t_activeTranslated = backupTranslated;
    } else {
        OriginalRenderText(pThis, text, x, y, color, unknown);
    }
}

// Hooked GetWordIncWidth from Engine.dll
int __fastcall MyGetWordIncWidth(void* pThis, void* edx, const char* text, int unknown) {
    if (!text || text[0] == '\0') {
        return OriginalGetWordIncWidth(pThis, text, unknown);
    }
    
    std::wstring standardWide = GetWideString(text);
    std::wstring vietWStr;
    bool translated = false;
    
    if (IsChineseString(standardWide)) {
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_translationCache.find(standardWide);
        if (it != g_translationCache.end()) {
            vietWStr = it->second;
            translated = true;
        }
    }
    
    if (translated) {
        int len = vietWStr.length();
        std::string dummy(len, 'a');
        for (int i = 0; i < len; i++) {
            dummy[i] = 'a' + (i % 26);
        }
        
        std::string backupDummy = t_activeDummy;
        std::wstring backupTranslated = t_activeTranslated;
        
        t_activeDummy = dummy;
        t_activeTranslated = vietWStr;
        t_lastMatchedOffset = 0; // RESET offset tracker
        
        int result = OriginalGetWordIncWidth(pThis, dummy.c_str(), unknown);
        
        t_activeDummy = backupDummy;
        t_activeTranslated = backupTranslated;
        return result;
    }
    
    return OriginalGetWordIncWidth(pThis, text, unknown);
}

// Hooked Font creation
HFONT WINAPI MyCreateFontIndirectW(LOGFONTW* lplf) {
    if (lplf) {
        lplf->lfCharSet = DEFAULT_CHARSET;
        wcscpy_s(lplf->lfFaceName, LF_FACESIZE, L"Arial");
    }
    return OriginalCreateFontIndirectW(lplf);
}

HFONT WINAPI MyCreateFontW(
    int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight,
    DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet,
    DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality,
    DWORD iPitchAndFamily, LPCWSTR pszFaceName
) {
    return OriginalCreateFontW(
        cHeight, cWidth, cEscapement, cOrientation, cWeight,
        bItalic, bUnderline, bStrikeOut, DEFAULT_CHARSET,
        iOutPrecision, iClipPrecision, iQuality,
        iPitchAndFamily, L"Arial"
    );
}

// Hooked GDI drawing (fallback/insurance)
BOOL WINAPI MyExtTextOutW(HDC hdc, int x, int y, UINT options, const RECT* lprect, LPCWSTR lpString, UINT c, const int* lpDx) {
    if (lpString && c > 0) {
        std::wstring original(lpString, c);
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_translationCache.find(original);
        if (it != g_translationCache.end()) {
            return OriginalExtTextOutW(hdc, x, y, options, lprect, it->second.c_str(), it->second.size(), lpDx);
        } else {
            if (IsChineseString(original)) {
                RequestTranslation(original);
            }
        }
    }
    return OriginalExtTextOutW(hdc, x, y, options, lprect, lpString, c, lpDx);
}

int WINAPI MyDrawTextW(HDC hdc, LPCWSTR lpchText, int cchText, LPRECT lprc, UINT format) {
    if (lpchText && cchText != 0) {
        int actualLen = (cchText < 0) ? wcslen(lpchText) : cchText;
        std::wstring original(lpchText, actualLen);
        std::lock_guard<std::mutex> lock(g_cacheMutex);
        auto it = g_translationCache.find(original);
        if (it != g_translationCache.end()) {
            return OriginalDrawTextW(hdc, it->second.c_str(), it->second.size(), lprc, format);
        } else {
            if (IsChineseString(original)) {
                RequestTranslation(original);
            }
        }
    }
    return OriginalDrawTextW(hdc, lpchText, cchText, lprc, format);
}

// Background thread to receive translations
void ReceiverThreadFunc() {
    std::vector<char> buffer(65536);
    sockaddr_in fromAddr;
    int fromLen = sizeof(fromAddr);
    
    while (g_running) {
        int bytesRecv = recvfrom(g_udpSocket, buffer.data(), buffer.size() - 2, 0, (struct sockaddr*)&fromAddr, &fromLen);
        if (bytesRecv > 0) {
            wchar_t* wBuf = (wchar_t*)buffer.data();
            int wLen = bytesRecv / sizeof(wchar_t);
            wBuf[wLen] = L'\0';
            
            std::wstring dataStr(wBuf, wLen);
            size_t delim = dataStr.find(L'|');
            if (delim != std::wstring::npos) {
                std::wstring chinese = dataStr.substr(0, delim);
                std::wstring vietnamese = dataStr.substr(delim + 1);
                
                std::lock_guard<std::mutex> lock(g_cacheMutex);
                g_translationCache[chinese] = vietnamese;
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void InitializeSocketsAndHooks() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;
    
    g_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_udpSocket == INVALID_SOCKET) return;
    
    u_long mode = 1;
    ioctlsocket(g_udpSocket, FIONBIO, &mode);
    
    sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_port = htons(0);
    localAddr.sin_addr.s_addr = INADDR_ANY;
    bind(g_udpSocket, (struct sockaddr*)&localAddr, sizeof(localAddr));
    
    g_serverAddr.sin_family = AF_INET;
    g_serverAddr.sin_port = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &g_serverAddr.sin_addr);
    
    g_running = true;
    g_receiverThread = std::thread(ReceiverThreadFunc);
    
    // Core String Decode Hook
    void* pMultiByteToWideChar = (void*)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "MultiByteToWideChar");
    if (!pMultiByteToWideChar) {
        pMultiByteToWideChar = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "MultiByteToWideChar");
    }
    if (pMultiByteToWideChar) {
        InstallHook(hookMultiByteToWideChar, pMultiByteToWideChar, (void*)MyMultiByteToWideChar);
    }
    
    // Core Engine Hooks
    void* pRenderText = (void*)GetProcAddress(GetModuleHandleA("Engine.dll"), "?RenderText@IGraph@@QAEXPBDHHKH@Z");
    if (pRenderText) {
        InstallHook(hookRenderText, pRenderText, (void*)MyRenderText);
    }
    
    void* pGetWordIncWidth = (void*)GetProcAddress(GetModuleHandleA("Engine.dll"), "?GetWordIncWidth@IGraph@@QAEHPBDH@Z");
    if (pGetWordIncWidth) {
        InstallHook(hookGetWordIncWidth, pGetWordIncWidth, (void*)MyGetWordIncWidth);
    }
    
    // Font Customization Hooks (Uncommented to fix font formatting issues and force Arial)
    void* pCreateFontIndirectW = (void*)GetProcAddress(GetModuleHandleA("gdi32full.dll"), "CreateFontIndirectW");
    if (!pCreateFontIndirectW) {
        pCreateFontIndirectW = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "CreateFontIndirectW");
    }
    if (pCreateFontIndirectW) {
        InstallHook(hookCreateFontIndirectW, pCreateFontIndirectW, (void*)MyCreateFontIndirectW);
    }
    
    void* pCreateFontW = (void*)GetProcAddress(GetModuleHandleA("gdi32full.dll"), "CreateFontW");
    if (!pCreateFontW) {
        pCreateFontW = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "CreateFontW");
    }
    if (pCreateFontW) {
        InstallHook(hookCreateFontW, pCreateFontW, (void*)MyCreateFontW);
    }
    
    // Standard GDI Fallbacks
    void* pExtTextOutW = (void*)GetProcAddress(GetModuleHandleA("gdi32.dll"), "ExtTextOutW");
    if (pExtTextOutW) {
        InstallHook(hookExtTextOutW, pExtTextOutW, (void*)MyExtTextOutW);
    }
    
    void* pDrawTextW = (void*)GetProcAddress(GetModuleHandleA("user32.dll"), "DrawTextW");
    if (pDrawTextW) {
        InstallHook(hookDrawTextW, pDrawTextW, (void*)MyDrawTextW);
    }
}

void CleanupSocketsAndHooks() {
    g_running = false;
    if (g_receiverThread.joinable()) {
        g_receiverThread.join();
    }
    
    UninstallHook(hookMultiByteToWideChar);
    UninstallHook(hookRenderText);
    UninstallHook(hookGetWordIncWidth);
    UninstallHook(hookCreateFontIndirectW);
    UninstallHook(hookCreateFontW);
    UninstallHook(hookExtTextOutW);
    UninstallHook(hookDrawTextW);
    
    if (g_udpSocket != INVALID_SOCKET) {
        closesocket(g_udpSocket);
    }
    WSACleanup();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeSocketsAndHooks();
        break;
    case DLL_PROCESS_DETACH:
        CleanupSocketsAndHooks();
        break;
    }
    return TRUE;
}
