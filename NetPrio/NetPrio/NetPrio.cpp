// NetPrioBackend.cpp
// Single-file backend: WinDivert traffic monitor + TCP server for GUI (JSON lines)
//
// Build: link ws2_32.lib, iphlpapi.lib
// Needs: windivert.h + WinDivert.dll in exe folder, driver installed
// Run as Admin (WinDivertOpen otherwise fails with ERROR_ACCESS_DENIED)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <array>
#include <cstring>
#include <fstream>
#include <sstream>
#include <exception>

#include <eh.h>   // _set_se_translator

#include "windivert.h"
#include "json.hpp" // nlohmann::json single header
using json = nlohmann::json;

// ============================================================
// WinAPI lock wrappers (NO std::mutex anywhere)
// ============================================================
struct SrwExclusiveGuard
{
    SRWLOCK* lock = nullptr;
    explicit SrwExclusiveGuard(SRWLOCK& l) : lock(&l) { AcquireSRWLockExclusive(lock); }
    ~SrwExclusiveGuard() { ReleaseSRWLockExclusive(lock); }
    SrwExclusiveGuard(const SrwExclusiveGuard&) = delete;
    SrwExclusiveGuard& operator=(const SrwExclusiveGuard&) = delete;
};

// ============================================================
// Logging helpers (console + file + OutputDebugString)
// ============================================================

static INIT_ONCE g_logInitOnce = INIT_ONCE_STATIC_INIT;
static CRITICAL_SECTION g_logCs;

static BOOL CALLBACK InitLogCsFn(PINIT_ONCE, PVOID, PVOID*)
{
    InitializeCriticalSection(&g_logCs);
    return TRUE;
}

static void LogLock()
{
    InitOnceExecuteOnce(&g_logInitOnce, InitLogCsFn, nullptr, nullptr);
    EnterCriticalSection(&g_logCs);
}

static void LogUnlock()
{
    LeaveCriticalSection(&g_logCs);
}

struct LogGuard
{
    LogGuard() { LogLock(); }
    ~LogGuard() { LogUnlock(); }
};

static std::ofstream g_logFile;

static std::string NowTimestamp()
{
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        (int)st.wYear, (int)st.wMonth, (int)st.wDay,
        (int)st.wHour, (int)st.wMinute, (int)st.wSecond, (int)st.wMilliseconds);
    return buf;
}

static DWORD ThreadId()
{
    return GetCurrentThreadId();
}

static std::string Win32ErrorToString(DWORD err)
{
    if (err == 0) return "OK";
    LPSTR msgBuf = nullptr;
    DWORD size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&msgBuf,
        0,
        nullptr
    );
    std::string msg = (size && msgBuf) ? std::string(msgBuf, size) : std::string("Unknown error");
    if (msgBuf) LocalFree(msgBuf);
    while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n')) msg.pop_back();
    return msg;
}

static void LogLine(const char* level, const std::string& s)
{
    LogGuard g;
    std::ostringstream oss;
    oss << "[" << NowTimestamp() << "]"
        << "[T" << ThreadId() << "]"
        << "[" << level << "] "
        << s;

    const std::string line = oss.str();
    std::cout << line << std::endl;
    OutputDebugStringA((line + "\n").c_str());

    if (g_logFile.is_open())
    {
        g_logFile << line << "\n";
        g_logFile.flush();
    }
}

static void LOGI(const std::string& s) { LogLine("INFO", s); }
static void LOGW(const std::string& s) { LogLine("WARN", s); }
static void LOGE(const std::string& s) { LogLine("ERR ", s); }

static bool HasConsole()
{
    return GetConsoleWindow() != nullptr;
}

static void PauseAlways()
{
    if (HasConsole())
        system("pause");
}

static int PauseAndReturn(int code)
{
    std::ostringstream oss;
    oss << "Exiting with code " << code;
    LOGW(oss.str());
    PauseAlways();
    return code;
}

// ============================================================
// Crash / unhandled exception handler
// ============================================================
static LONG WINAPI UnhandledExceptionFilterFunc(EXCEPTION_POINTERS* ep)
{
    DWORD code = ep ? ep->ExceptionRecord->ExceptionCode : 0;
    std::ostringstream oss;
    oss << "UNHANDLED EXCEPTION! Code=0x" << std::hex << code;

    if (ep && ep->ExceptionRecord)
        oss << " Address=" << ep->ExceptionRecord->ExceptionAddress;

    LOGE(oss.str());

    DWORD gle = GetLastError();
    std::ostringstream oss2;
    oss2 << "GetLastError=" << std::dec << gle << " (" << Win32ErrorToString(gle) << ")";
    LOGE(oss2.str());

    PauseAlways();
    return EXCEPTION_EXECUTE_HANDLER;
}

// ============================================================
// SEH -> C++ Exception translator (needs /EHa to be catchable)
// ============================================================
struct SehException : public std::exception
{
    unsigned int code;
    void* address;
    SehException(unsigned int c, void* a) : code(c), address(a) {}
    const char* what() const noexcept override { return "SEH exception (translated)"; }
};

static void SehTranslator(unsigned int code, EXCEPTION_POINTERS* ep)
{
    void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
    throw SehException(code, addr);
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0)
    {
        DWORD gle = GetLastError();
        std::ostringstream oss;
        oss << "WideCharToMultiByte size failed. GLE=" << gle << " (" << Win32ErrorToString(gle) << ")";
        LOGW(oss.str());
        return {};
    }
    std::string out;
    out.resize((size_t)len);
    int ok = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len, nullptr, nullptr);
    if (ok <= 0)
    {
        DWORD gle = GetLastError();
        std::ostringstream oss;
        oss << "WideCharToMultiByte convert failed. GLE=" << gle << " (" << Win32ErrorToString(gle) << ")";
        LOGW(oss.str());
        return {};
    }
    return out;
}

static inline void SetAddrV4(std::array<uint8_t, 16>& dst, UINT32 v4)
{
    dst.fill(0);
    std::memcpy(dst.data(), &v4, sizeof(v4));
}

static inline void SetAddrV6(std::array<uint8_t, 16>& dst, const void* v6_16bytes)
{
    std::memcpy(dst.data(), v6_16bytes, 16);
}

// ------------------------------------------------------------
// TeamViewer helpers
// ------------------------------------------------------------
static bool IsTeamViewerProcessName(const std::wstring& exe)
{
    if (_wcsicmp(exe.c_str(), L"TeamViewer.exe") == 0) return true;
    if (_wcsicmp(exe.c_str(), L"TeamViewer_Service.exe") == 0) return true;
    if (_wcsicmp(exe.c_str(), L"tv_x64.exe") == 0) return true;
    if (_wcsicmp(exe.c_str(), L"tv_w32.exe") == 0) return true;
    if (exe.size() >= 9 && _wcsnicmp(exe.c_str(), L"TeamViewer", 9) == 0) return true;
    return false;
}

static bool IsAnyTeamViewerRunning()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe))
    {
        CloseHandle(snap);
        return false;
    }

    bool found = false;
    do
    {
        if (IsTeamViewerProcessName(pe.szExeFile))
        {
            found = true;
            break;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return found;
}

// ------------------------------------------------------------
// Data structures
// ------------------------------------------------------------
struct ConnKey
{
    bool isV6 = false;
    std::array<uint8_t, 16> localAddr{};
    std::array<uint8_t, 16> remoteAddr{};
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    UINT8 protocol = 0;

    bool operator==(const ConnKey& o) const noexcept
    {
        return isV6 == o.isV6 &&
            localAddr == o.localAddr &&
            remoteAddr == o.remoteAddr &&
            localPort == o.localPort &&
            remotePort == o.remotePort &&
            protocol == o.protocol;
    }
};

struct ConnKeyHash
{
    static inline std::size_t HashBytes16(const std::array<uint8_t, 16>& a) noexcept
    {
        uint64_t x = 0, y = 0;
        std::memcpy(&x, a.data(), 8);
        std::memcpy(&y, a.data() + 8, 8);
        std::size_t h1 = std::hash<uint64_t>{}(x);
        std::size_t h2 = std::hash<uint64_t>{}(y);
        return h1 ^ (h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2));
    }

    std::size_t operator()(const ConnKey& k) const noexcept
    {
        std::size_t hA = HashBytes16(k.localAddr);
        std::size_t hB = HashBytes16(k.remoteAddr);
        std::size_t hP1 = std::hash<UINT16>{}(k.localPort);
        std::size_t hP2 = std::hash<UINT16>{}(k.remotePort);
        std::size_t hProto = std::hash<UINT8>{}(k.protocol);
        std::size_t hV6 = std::hash<bool>{}(k.isV6);

        std::size_t h = hA;
        h ^= (hB + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        h ^= (hP1 + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        h ^= (hP2 + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        h ^= (hProto + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        h ^= (hV6 + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2));
        return h;
    }
};

struct TrafficCounters
{
    unsigned long long uploadBytes = 0;
    unsigned long long downloadBytes = 0;
};

enum class PriorityLevel : int
{
    High = 1,
    Medium = 2,
    Low = 3,
    Unspecified = 99
};

struct PriorityProfile
{
    double minKBps = 0.0;
    double maxKBps = 0.0;
};

struct TokenBucket
{
    double maxKBps = 0.0;
    double tokensBytes = 0.0;
    std::chrono::steady_clock::time_point last;
    bool initialized = false;

    void Reset(double kbps)
    {
        maxKBps = kbps;
        tokensBytes = 0.0;
        initialized = false;
    }

    bool AllowBytes(UINT bytes)
    {
        if (maxKBps <= 0.0) return false;

        auto now = std::chrono::steady_clock::now();
        if (!initialized)
        {
            last = now;
            initialized = true;
            tokensBytes = 0.0;
        }

        double dt = std::chrono::duration<double>(now - last).count();
        last = now;

        double rateBytesPerSec = maxKBps * 1024.0;
        tokensBytes += rateBytesPerSec * dt;

        double maxTokens = rateBytesPerSec;
        if (tokensBytes > maxTokens) tokensBytes = maxTokens;

        if (tokensBytes >= (double)bytes)
        {
            tokensBytes -= (double)bytes;
            return true;
        }
        return false;
    }
};

// ------------------------------------------------------------
// Global socket server state (NO std::mutex)
// ------------------------------------------------------------
static std::atomic_bool g_running(true);
static SOCKET g_clientSocket = INVALID_SOCKET;
static SRWLOCK g_clientLock = SRWLOCK_INIT;

static std::atomic_bool g_teamViewerBypassLogged(false);

// ✅ Limiter ON/OFF state:
// OFF => sniff mode (no reinject -> full speed)
// ON  => divert mode (reinject + rate-limit)
static std::atomic_bool g_limiterEnabled(false);

static void SendJsonLine(const std::string& line)
{
    SrwExclusiveGuard g(g_clientLock);
    if (g_clientSocket == INVALID_SOCKET) return;

    std::string msg = line + "\n";
    int r = send(g_clientSocket, msg.c_str(), (int)msg.size(), 0);
    if (r == SOCKET_ERROR)
    {
        int wsa = WSAGetLastError();
        std::ostringstream oss;
        oss << "send() failed. WSA=" << wsa;
        LOGW(oss.str());
    }
}

// ------------------------------------------------------------
// Windows process map
// ------------------------------------------------------------
static std::unordered_map<DWORD, std::wstring> BuildPidNameMap()
{
    std::unordered_map<DWORD, std::wstring> pidToName;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        DWORD gle = GetLastError();
        LOGW("CreateToolhelp32Snapshot failed. GLE=" + std::to_string(gle) + " (" + Win32ErrorToString(gle) + ")");
        return pidToName;
    }

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe))
    {
        DWORD gle = GetLastError();
        LOGW("Process32First failed. GLE=" + std::to_string(gle) + " (" + Win32ErrorToString(gle) + ")");
        CloseHandle(snap);
        return pidToName;
    }

    do { pidToName[pe.th32ProcessID] = pe.szExeFile; } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return pidToName;
}

// ------------------------------------------------------------
// Connection -> PID map
// ------------------------------------------------------------
static bool BuildConnectionPidMap(std::unordered_map<ConnKey, DWORD, ConnKeyHash>& connToPid)
{
    connToPid.clear();

    auto addTcp4 = [&](PMIB_TCPTABLE_OWNER_PID pTable)
        {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i)
            {
                const auto& row = pTable->table[i];
                ConnKey k{};
                k.isV6 = false;
                SetAddrV4(k.localAddr, row.dwLocalAddr);
                SetAddrV4(k.remoteAddr, row.dwRemoteAddr);
                k.localPort = ntohs((u_short)row.dwLocalPort);
                k.remotePort = ntohs((u_short)row.dwRemotePort);
                k.protocol = IPPROTO_TCP;
                connToPid[k] = row.dwOwningPid;
            }
        };

    auto addUdp4 = [&](PMIB_UDPTABLE_OWNER_PID pTable)
        {
            for (DWORD i = 0; i < pTable->dwNumEntries; ++i)
            {
                const auto& row = pTable->table[i];
                ConnKey k{};
                k.isV6 = false;
                SetAddrV4(k.localAddr, row.dwLocalAddr);
                k.remoteAddr.fill(0);
                k.localPort = ntohs((u_short)row.dwLocalPort);
                k.remotePort = 0;
                k.protocol = IPPROTO_UDP;
                connToPid[k] = row.dwOwningPid;
            }
        };

    auto addTcp6 = [&](PMIB_TCP6TABLE_OWNER_PID pTable6)
        {
            for (DWORD i = 0; i < pTable6->dwNumEntries; ++i)
            {
                const auto& row = pTable6->table[i];
                ConnKey k{};
                k.isV6 = true;
                SetAddrV6(k.localAddr, row.ucLocalAddr);
                SetAddrV6(k.remoteAddr, row.ucRemoteAddr);
                k.localPort = ntohs((u_short)row.dwLocalPort);
                k.remotePort = ntohs((u_short)row.dwRemotePort);
                k.protocol = IPPROTO_TCP;
                connToPid[k] = row.dwOwningPid;
            }
        };

    auto addUdp6 = [&](PMIB_UDP6TABLE_OWNER_PID pTable6)
        {
            for (DWORD i = 0; i < pTable6->dwNumEntries; ++i)
            {
                const auto& row = pTable6->table[i];
                ConnKey k{};
                k.isV6 = true;
                SetAddrV6(k.localAddr, row.ucLocalAddr);
                k.remoteAddr.fill(0);
                k.localPort = ntohs((u_short)row.dwLocalPort);
                k.remotePort = 0;
                k.protocol = IPPROTO_UDP;
                connToPid[k] = row.dwOwningPid;
            }
        };

    // TCP IPv4
    {
        DWORD size = 0;
        DWORD r = GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r != ERROR_INSUFFICIENT_BUFFER)
        {
            LOGE("GetExtendedTcpTable(AF_INET,size) unexpected: " + std::to_string(r));
            return false;
        }
        auto* pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (!pTable) { LOGE("malloc TCP table failed"); return false; }

        r = GetExtendedTcpTable(pTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r != NO_ERROR)
        {
            LOGE("GetExtendedTcpTable(AF_INET) failed: " + std::to_string(r));
            free(pTable);
            return false;
        }
        addTcp4(pTable);
        free(pTable);
    }

    // UDP IPv4
    {
        DWORD size = 0;
        DWORD r = GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (r != ERROR_INSUFFICIENT_BUFFER)
        {
            LOGE("GetExtendedUdpTable(AF_INET,size) unexpected: " + std::to_string(r));
            return false;
        }
        auto* pTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (!pTable) { LOGE("malloc UDP table failed"); return false; }

        r = GetExtendedUdpTable(pTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (r != NO_ERROR)
        {
            LOGE("GetExtendedUdpTable(AF_INET) failed: " + std::to_string(r));
            free(pTable);
            return false;
        }
        addUdp4(pTable);
        free(pTable);
    }

    // TCP IPv6
    {
        DWORD size = 0;
        DWORD r = GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r == ERROR_INSUFFICIENT_BUFFER)
        {
            auto* pTable6 = (PMIB_TCP6TABLE_OWNER_PID)malloc(size);
            if (!pTable6) { LOGE("malloc TCP6 table failed"); return false; }

            r = GetExtendedTcpTable(pTable6, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (r != NO_ERROR)
            {
                LOGE("GetExtendedTcpTable(AF_INET6) failed: " + std::to_string(r));
                free(pTable6);
                return false;
            }
            addTcp6(pTable6);
            free(pTable6);
        }
        else if (r != NO_ERROR)
        {
            LOGW("GetExtendedTcpTable(AF_INET6) returned: " + std::to_string(r) + " (ignored on some systems)");
        }
    }

    // UDP IPv6
    {
        DWORD size = 0;
        DWORD r = GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (r == ERROR_INSUFFICIENT_BUFFER)
        {
            auto* pTable6 = (PMIB_UDP6TABLE_OWNER_PID)malloc(size);
            if (!pTable6) { LOGE("malloc UDP6 table failed"); return false; }

            r = GetExtendedUdpTable(pTable6, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (r != NO_ERROR)
            {
                LOGE("GetExtendedUdpTable(AF_INET6) failed: " + std::to_string(r));
                free(pTable6);
                return false;
            }
            addUdp6(pTable6);
            free(pTable6);
        }
        else if (r != NO_ERROR)
        {
            LOGW("GetExtendedUdpTable(AF_INET6) returned: " + std::to_string(r) + " (ignored on some systems)");
        }
    }

    return true;
}

// ------------------------------------------------------------
// TrafficMonitor
// ------------------------------------------------------------
class TrafficMonitor
{
public:
    TrafficMonitor() {}
    ~TrafficMonitor() = default;

    bool Init()
    {
        LOGI("TrafficMonitor::Init() start");

        {
            SrwExclusiveGuard lock(mtx_);
            pidToName_ = BuildPidNameMap();
            if (!BuildConnectionPidMap(connToPid_))
            {
                LOGE("BuildConnectionPidMap failed");
                return false;
            }

            // default profiles (can be overwritten by GUI)
            profiles_[PriorityLevel::High] = { 0.0, 10000.0 };
            profiles_[PriorityLevel::Medium] = { 0.0, 5000.0 };
            profiles_[PriorityLevel::Low] = { 0.0, 1000.0 };
            profiles_[PriorityLevel::Unspecified] = { 0.0, 1000000.0 };
        }

        if (IsAnyTeamViewerRunning())
        {
            bool expected = false;
            if (g_teamViewerBypassLogged.compare_exchange_strong(expected, true))
            {
                LOGW("TeamViewer erkannt: Pakete werden NICHT gefiltert/limitiert, "
                    "weil Remote-Verbindung sonst abbrechen kann (gleiche Netzwerkschnittstelle).");
            }
        }

        // Default: SNIFF mode (no reinject -> no throughput cap)
        requestedMode_.store((int)CaptureMode::Sniff);
        currentMode_.store((int)CaptureMode::None);

        if (!ReopenHandleIfNeeded(/*force*/true))
            return false;

        LOGI("TrafficMonitor::Init() OK");
        return true;
    }

    void Shutdown()
    {
        LOGI("TrafficMonitor::Shutdown()");
        CloseHandle();
    }

    void RunCaptureLoop()
    {
        LOGI("TrafficMonitor::RunCaptureLoop() start");

        const UINT MAX_PACKET = 0xFFFF;
        std::vector<char> packet(MAX_PACKET);
        WINDIVERT_ADDRESS addr{};

        while (g_running)
        {
            // Switch mode if GUI changed limiter state
            if (!ReopenHandleIfNeeded(/*force*/false))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }

            UINT recvLen = 0;
            if (!WinDivertRecv(handle_, packet.data(), (UINT)packet.size(), &recvLen, &addr))
            {
                DWORD err = GetLastError();
                if (!g_running) break;

                LOGE("WinDivertRecv failed. GLE=" + std::to_string(err) + " (" + Win32ErrorToString(err) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }

            bool allow = true;
            try
            {
                allow = ProcessPacket(packet.data(), recvLen, addr);
            }
            catch (const SehException& se)
            {
                std::ostringstream oss;
                oss << "SEH exception in ProcessPacket: code=0x" << std::hex << se.code
                    << " addr=" << se.address;
                LOGE(oss.str());
                allow = true; // fail-open
            }
            catch (const std::exception& e)
            {
                LOGE(std::string("std::exception in ProcessPacket: ") + e.what());
                allow = true;
            }
            catch (...)
            {
                LOGE("Unknown exception in ProcessPacket");
                allow = true;
            }

            // ✅ IMPORTANT:
            // - In SNIFF mode we DO NOT reinject (WinDivert already lets packet pass).
            // - In DIVERT mode we MUST reinject allowed packets.
            CaptureMode mode = (CaptureMode)currentMode_.load();
            if (mode == CaptureMode::Divert)
            {
                if (allow)
                {
                    if (!WinDivertSend(handle_, packet.data(), recvLen, nullptr, &addr))
                    {
                        DWORD err = GetLastError();
                        LOGW("WinDivertSend failed. GLE=" + std::to_string(err) + " (" + Win32ErrorToString(err) + ")");
                    }
                }
                // else: drop by not re-injecting
            }
        }

        LOGW("TrafficMonitor::RunCaptureLoop() ended");
    }

    void PublishStats(int intervalMs)
    {
        std::unordered_map<DWORD, TrafficCounters> snapshot;
        std::unordered_map<DWORD, PriorityLevel> prioSnapshot;
        std::unordered_map<DWORD, std::wstring> nameSnapshot;

        {
            SrwExclusiveGuard lock(mtx_);
            snapshot.swap(traffic_);
            prioSnapshot = pidPriority_;
            nameSnapshot = pidToName_;
        }

        double seconds = intervalMs / 1000.0;
        if (seconds <= 0.0) seconds = 1.0;

        try
        {
            json j;
            j["type"] = "STATS";
            j["interval_ms"] = intervalMs;
            j["processes"] = json::array();

            std::unordered_map<DWORD, bool> include;
            include.reserve(snapshot.size() + prioSnapshot.size());
            for (auto& kv : snapshot) include[kv.first] = true;
            for (auto& kv : prioSnapshot) include[kv.first] = true;

            for (auto& kv : include)
            {
                DWORD pid = kv.first;

                TrafficCounters tc{};
                auto itT = snapshot.find(pid);
                if (itT != snapshot.end()) tc = itT->second;

                PriorityLevel lvl = PriorityLevel::Unspecified;
                auto itP = prioSnapshot.find(pid);
                if (itP != prioSnapshot.end()) lvl = itP->second;

                std::string name = "<unknown>";
                auto itN = nameSnapshot.find(pid);
                if (itN != nameSnapshot.end())
                {
                    name = WideToUtf8(itN->second);
                    if (name.empty()) name = "<unknown>";
                }

                double downKBs = (tc.downloadBytes / 1024.0) / seconds;
                double upKBs = (tc.uploadBytes / 1024.0) / seconds;

                j["processes"].push_back({
                    {"pid", pid},
                    {"name", name},
                    {"prio", (int)lvl},
                    {"down_kbps", downKBs},
                    {"up_kbps", upKBs}
                    });
            }

            SendJsonLine(j.dump());
        }
        catch (...)
        {
            LOGE("PublishStats unknown exception");
        }

        static int tick = 0;
        tick++;
        if (tick % 2 == 0)
        {
            SrwExclusiveGuard lock(mtx_);
            pidToName_ = BuildPidNameMap();
            if (!BuildConnectionPidMap(connToPid_))
                LOGW("BuildConnectionPidMap failed in refresh (keeping old map)");
        }
    }

    void SetPriorityProfile(PriorityLevel level, double minKBps, double maxKBps)
    {
        SrwExclusiveGuard lock(mtx_);
        profiles_[level] = { minKBps, maxKBps };

        // Update existing buckets (only matters in limiter mode)
        for (auto& kv : pidBuckets_)
        {
            DWORD pid = kv.first;
            PriorityLevel lvl = PriorityLevel::Low;
            auto itP = pidPriority_.find(pid);
            if (itP != pidPriority_.end()) lvl = itP->second;
            if (lvl == PriorityLevel::Unspecified) lvl = PriorityLevel::Low;

            double cap = GetProfileMaxKBps_NoLock(lvl);
            kv.second.Reset(cap);
        }

        LOGI("SetPriorityProfile level=" + std::to_string((int)level) + " maxKBps=" + std::to_string(maxKBps));
    }

    void ClearAllPriorities_DisableLimiter()
    {
        SrwExclusiveGuard lock(mtx_);
        pidPriority_.clear();
        pidBuckets_.clear();

        g_limiterEnabled.store(false);
        requestedMode_.store((int)CaptureMode::Sniff);

        LOGW("Limiter deaktiviert: SNIFF Mode (ungefiltert, kein Reinjection-Overhead).");
    }

    void SetPriority(DWORD pid, PriorityLevel level)
    {
        SrwExclusiveGuard lock(mtx_);
        pidPriority_[pid] = level;

        // Enable limiter only if real priority
        if (level == PriorityLevel::High || level == PriorityLevel::Medium || level == PriorityLevel::Low)
        {
            g_limiterEnabled.store(true);
            requestedMode_.store((int)CaptureMode::Divert);
        }

        PriorityLevel eff = level;
        if (eff == PriorityLevel::Unspecified) eff = PriorityLevel::Low;

        double cap = GetProfileMaxKBps_NoLock(eff);
        pidBuckets_[pid].Reset(cap);

        LOGI("SetPriority pid=" + std::to_string(pid) +
            " level=" + std::to_string((int)level) +
            " capKBps=" + std::to_string(cap));
    }

private:
    enum class CaptureMode : int { None = 0, Sniff = 1, Divert = 2 };

    HANDLE handle_ = INVALID_HANDLE_VALUE;
    SRWLOCK mtx_ = SRWLOCK_INIT;

    std::atomic_int requestedMode_{ (int)CaptureMode::Sniff };
    std::atomic_int currentMode_{ (int)CaptureMode::None };

    std::unordered_map<ConnKey, DWORD, ConnKeyHash> connToPid_;
    std::unordered_map<DWORD, std::wstring> pidToName_;
    std::unordered_map<DWORD, TrafficCounters> traffic_;
    std::unordered_map<DWORD, PriorityLevel> pidPriority_;
    std::unordered_map<PriorityLevel, PriorityProfile> profiles_;
    std::unordered_map<DWORD, TokenBucket> pidBuckets_;

private:
    void CloseHandle()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
        currentMode_.store((int)CaptureMode::None);
    }

    bool OpenHandle(CaptureMode mode)
    {
        CloseHandle();

        const char* filter = "((ip or ipv6) and (tcp or udp))";
        UINT64 flags = 0;

        if (mode == CaptureMode::Sniff)
            flags = WINDIVERT_FLAG_SNIFF; // capture copy, do NOT block, no reinject needed
        else
            flags = 0; // divert (block + reinject)

        LOGI(std::string("WinDivertOpen mode=") + (mode == CaptureMode::Sniff ? "SNIFF" : "DIVERT") + "...");

        handle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, flags);
        if (handle_ == INVALID_HANDLE_VALUE)
        {
            DWORD gle = GetLastError();
            std::ostringstream oss;
            oss << "WinDivertOpen failed. Mode=" << (mode == CaptureMode::Sniff ? "SNIFF" : "DIVERT")
                << " GLE=" << gle << " (" << Win32ErrorToString(gle) << ").";
            LOGE(oss.str());
            return false;
        }

        currentMode_.store((int)mode);
        LOGI("WinDivertOpen OK.");
        return true;
    }

    bool ReopenHandleIfNeeded(bool force)
    {
        CaptureMode want = (CaptureMode)requestedMode_.load();
        CaptureMode cur = (CaptureMode)currentMode_.load();

        if (!force && want == cur)
            return true;

        // reopen with requested mode
        if (!OpenHandle(want))
            return false;

        return true;
    }

    double GetProfileMaxKBps_NoLock(PriorityLevel lvl) const
    {
        auto it = profiles_.find(lvl);
        if (it != profiles_.end()) return it->second.maxKBps;
        auto itU = profiles_.find(PriorityLevel::Unspecified);
        if (itU != profiles_.end()) return itU->second.maxKBps;
        return 1000000.0;
    }

    bool ProcessPacket(char* packet, UINT recvLen, const WINDIVERT_ADDRESS& addr)
    {
        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_IPV6HDR ipv6 = nullptr;
        UINT8 protocol = 0;
        PWINDIVERT_TCPHDR tcp = nullptr;
        PWINDIVERT_UDPHDR udp = nullptr;

        if (!WinDivertHelperParsePacket(packet, recvLen, &ip, &ipv6, &protocol, nullptr, nullptr, &tcp, &udp, nullptr, nullptr, nullptr, nullptr))
            return true;

        const bool isTcp = (protocol == IPPROTO_TCP);
        const bool isUdp = (protocol == IPPROTO_UDP);
        if (!isTcp && !isUdp) return true;
        if (isTcp && !tcp) return true;
        if (isUdp && !udp) return true;

        const bool isV4 = (ip != nullptr);
        const bool isV6 = (ipv6 != nullptr);
        if (!isV4 && !isV6) return true;

        ConnKey key{};
        key.isV6 = isV6;
        key.protocol = isTcp ? IPPROTO_TCP : IPPROTO_UDP;

        if (isV4)
        {
            if (addr.Outbound)
            {
                SetAddrV4(key.localAddr, ip->SrcAddr);
                SetAddrV4(key.remoteAddr, ip->DstAddr);
                key.localPort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
                key.remotePort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
            }
            else
            {
                SetAddrV4(key.localAddr, ip->DstAddr);
                SetAddrV4(key.remoteAddr, ip->SrcAddr);
                key.localPort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
                key.remotePort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
            }
        }
        else
        {
            if (addr.Outbound)
            {
                SetAddrV6(key.localAddr, ipv6->SrcAddr);
                SetAddrV6(key.remoteAddr, ipv6->DstAddr);
                key.localPort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
                key.remotePort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
            }
            else
            {
                SetAddrV6(key.localAddr, ipv6->DstAddr);
                SetAddrV6(key.remoteAddr, ipv6->SrcAddr);
                key.localPort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
                key.remotePort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
            }
        }

        SrwExclusiveGuard lock(mtx_);

        auto it = connToPid_.find(key);
        if (it == connToPid_.end() && isUdp)
        {
            ConnKey localOnly = key;
            localOnly.remoteAddr.fill(0);
            localOnly.remotePort = 0;
            it = connToPid_.find(localOnly);
        }
        if (it == connToPid_.end())
            return true;

        DWORD pid = it->second;

        // count traffic always
        if (addr.Outbound) traffic_[pid].uploadBytes += recvLen;
        else traffic_[pid].downloadBytes += recvLen;

        // TeamViewer bypass: never limit its packets (in DIVERT mode too)
        auto itName = pidToName_.find(pid);
        if (itName != pidToName_.end() && IsTeamViewerProcessName(itName->second))
        {
            bool expected = false;
            if (g_teamViewerBypassLogged.compare_exchange_strong(expected, true))
            {
                LOGW("TeamViewer erkannt: Pakete werden NICHT gefiltert/limitiert, "
                    "weil Remote-Verbindung sonst abbrechen kann (gleiche Netzwerkschnittstelle).");
            }
            return true;
        }

        // if limiter disabled => always allow
        if (!g_limiterEnabled.load())
            return true;

        // limiter ON:
        // - if pid has explicit prio => use it
        // - else => treat as LOW (throttle everyone else)
        PriorityLevel lvl = PriorityLevel::Low;
        auto itP = pidPriority_.find(pid);
        if (itP != pidPriority_.end())
            lvl = itP->second;

        if (lvl == PriorityLevel::Unspecified)
            lvl = PriorityLevel::Low;

        double cap = GetProfileMaxKBps_NoLock(lvl);

        auto itB = pidBuckets_.find(pid);
        if (itB == pidBuckets_.end())
        {
            TokenBucket b{};
            b.Reset(cap);
            pidBuckets_[pid] = b;
            itB = pidBuckets_.find(pid);
        }
        else
        {
            if (itB->second.maxKBps != cap)
                itB->second.Reset(cap);
        }

        return itB->second.AllowBytes(recvLen);
    }
};

// ------------------------------------------------------------
// JSON commands from GUI
// ------------------------------------------------------------
static TrafficMonitor* g_monitor = nullptr;

static void HandleJsonCommand(const std::string& line)
{
    if (!g_monitor) return;

    json j = json::parse(line, nullptr, false);
    if (j.is_discarded())
    {
        LOGW("JSON parse error (discarded). Line=" + line);
        return;
    }

    std::string type = j.value("type", "");

    if (type == "SET_PROFILES")
    {
        auto profs = j["profiles"];
        double highMax = profs["high"].value("max_kbps", 10000.0);
        double medMax = profs["medium"].value("max_kbps", 5000.0);
        double lowMax = profs["low"].value("max_kbps", 1000.0);

        g_monitor->SetPriorityProfile(PriorityLevel::High, 0.0, highMax);
        g_monitor->SetPriorityProfile(PriorityLevel::Medium, 0.0, medMax);
        g_monitor->SetPriorityProfile(PriorityLevel::Low, 0.0, lowMax);
        LOGI("SET_PROFILES ok");
    }
    else if (type == "SET_PRIORITIES")
    {
        if (!j.contains("priorities") || !j["priorities"].is_array())
        {
            LOGW("SET_PRIORITIES missing/invalid 'priorities' array");
            return;
        }

        // If the list contains NO real priority (1..3), disable limiter (=> sniff).
        bool anyReal = false;
        for (auto& item : j["priorities"])
        {
            int lvlInt = item.value("level", 99);
            if (lvlInt == 1 || lvlInt == 2 || lvlInt == 3)
            {
                anyReal = true;
                break;
            }
        }

        if (!anyReal)
        {
            g_monitor->ClearAllPriorities_DisableLimiter();
            LOGI("SET_PRIORITIES: no real priorities -> limiter OFF (sniff)");
            return;
        }

        // Real priorities exist -> apply and enable limiter
        for (auto& item : j["priorities"])
        {
            DWORD pid = item.value("pid", 0u);
            int lvlInt = item.value("level", 99);
            PriorityLevel lvl = (PriorityLevel)lvlInt;
            if (pid != 0)
                g_monitor->SetPriority(pid, lvl);
        }

        LOGI("SET_PRIORITIES ok (limiter ON => divert)");
    }
    else
    {
        LOGW("Unknown command type: " + type);
    }
}

// ------------------------------------------------------------
// TCP server for GUI
// ------------------------------------------------------------
static void HandleClientCommands(SOCKET client)
{
    LOGI("HandleClientCommands thread start");
    char buffer[4096];
    std::string pending;

    while (g_running)
    {
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n == 0) { LOGI("Client closed connection (recv=0)"); break; }
        if (n < 0)
        {
            int wsa = WSAGetLastError();
            LOGW("recv() failed. WSA=" + std::to_string(wsa));
            break;
        }

        pending.append(buffer, n);
        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos)
        {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty())
            {
                try { HandleJsonCommand(line); }
                catch (const SehException& se)
                {
                    std::ostringstream oss;
                    oss << "SEH exception handling command: code=0x" << std::hex << se.code
                        << " addr=" << se.address;
                    LOGE(oss.str());
                }
                catch (const std::exception& e) { LOGE(std::string("Exception handling command: ") + e.what()); }
                catch (...) { LOGE("Unknown exception handling command"); }
            }
        }
    }

    closesocket(client);

    {
        SrwExclusiveGuard g(g_clientLock);
        if (g_clientSocket == client) g_clientSocket = INVALID_SOCKET;
    }

    LOGI("GUI disconnected");
}

static void ServerThreadFunc()
{
    LOGI("ServerThreadFunc start");

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        int wsae = WSAGetLastError();
        LOGE("WSAStartup failed. WSA=" + std::to_string(wsae));
        return;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET)
    {
        int wsae = WSAGetLastError();
        LOGE("socket() failed. WSA=" + std::to_string(wsae));
        WSACleanup();
        return;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(5555);

    if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        int wsae = WSAGetLastError();
        LOGE("bind() failed. WSA=" + std::to_string(wsae) + " (Port 5555 already in use?)");
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    if (listen(listenSock, 1) == SOCKET_ERROR)
    {
        int wsae = WSAGetLastError();
        LOGE("listen() failed. WSA=" + std::to_string(wsae));
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    LOGI("TCP server listening on 127.0.0.1:5555");

    while (g_running)
    {
        SOCKET client = accept(listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET)
        {
            if (!g_running) break;
            int wsae = WSAGetLastError();
            LOGW("accept() failed. WSA=" + std::to_string(wsae));
            continue;
        }

        {
            SrwExclusiveGuard g(g_clientLock);
            if (g_clientSocket != INVALID_SOCKET)
            {
                LOGW("Replacing existing GUI client socket");
                closesocket(g_clientSocket);
            }
            g_clientSocket = client;
        }

        LOGI("GUI connected");
        std::thread(HandleClientCommands, client).detach();
    }

    closesocket(listenSock);
    WSACleanup();
    LOGW("ServerThreadFunc end");
}

// ------------------------------------------------------------
// Stats publisher thread
// ------------------------------------------------------------
static void StatsThreadFunc()
{
    constexpr int intervalMs = 1000;
    LOGI("StatsThreadFunc start (intervalMs=1000)");

    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        if (g_monitor)
        {
            try { g_monitor->PublishStats(intervalMs); }
            catch (...) { LOGE("PublishStats unknown exception"); }
        }
    }

    LOGW("StatsThreadFunc end");
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main()
{
    PauseAlways();

    g_logFile.open("netprio_backend.log", std::ios::out | std::ios::app);

    LOGI("============================================================");
    LOGI("NetPrioBackend starting...");

    SetUnhandledExceptionFilter(UnhandledExceptionFilterFunc);
    _set_se_translator(SehTranslator);

    {
        char cwd[MAX_PATH]{};
        GetCurrentDirectoryA(MAX_PATH, cwd);
        LOGI(std::string("CWD=") + cwd);
    }

    std::thread serverThread;
    std::thread statsThread;

    try
    {
        serverThread = std::thread(ServerThreadFunc);

        TrafficMonitor monitor;
        g_monitor = &monitor;

        if (!monitor.Init())
        {
            LOGE("monitor.Init() failed -> terminating.");
            g_running = false;
            if (serverThread.joinable()) serverThread.join();
            return PauseAndReturn(1);
        }

        statsThread = std::thread(StatsThreadFunc);

        LOGI("Backend READY. Entering capture loop...");
        monitor.RunCaptureLoop();

        LOGW("Capture loop returned (unexpected unless stopping).");
        g_running = false;
        monitor.Shutdown();

        if (statsThread.joinable()) statsThread.join();
        if (serverThread.joinable()) serverThread.join();

        LOGI("Normal shutdown complete.");
        return PauseAndReturn(0);
    }
    catch (const SehException& se)
    {
        std::ostringstream oss;
        oss << "SEH exception in main: code=0x" << std::hex << se.code
            << " addr=" << se.address;
        LOGE(oss.str());

        g_running = false;
        if (statsThread.joinable()) statsThread.join();
        if (serverThread.joinable()) serverThread.join();
        return PauseAndReturn(999);
    }
    catch (const std::exception& e)
    {
        LOGE(std::string("std::exception in main: ") + e.what());
        g_running = false;
        if (statsThread.joinable()) statsThread.join();
        if (serverThread.joinable()) serverThread.join();
        return PauseAndReturn(998);
    }
    catch (...)
    {
        LOGE("Unknown exception in main");
        g_running = false;
        if (statsThread.joinable()) statsThread.join();
        if (serverThread.joinable()) serverThread.join();
        return PauseAndReturn(997);
    }
}
