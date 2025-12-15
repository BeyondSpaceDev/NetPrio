#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <iomanip>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "windivert.h"
#include "json.hpp"   // nlohmann::json (Single-Header)

using json = nlohmann::json;

// ------------------------------------------------------------
// Grunddatenstrukturen
// ------------------------------------------------------------

struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    double cpuPercent = 0.0; // CPU-Last in %
};

struct NetStats {
    unsigned long long inBytes;
    unsigned long long outBytes;
};

struct ConnKey
{
    UINT32 localAddr;
    UINT32 remoteAddr;
    UINT16 localPort;
    UINT16 remotePort;
    UINT8  protocol;   // z.B. IPPROTO_TCP

    bool operator==(const ConnKey& other) const noexcept {
        return localAddr == other.localAddr &&
            remoteAddr == other.remoteAddr &&
            localPort == other.localPort &&
            remotePort == other.remotePort &&
            protocol == other.protocol;
    }
};

struct ConnKeyHash
{
    std::size_t operator()(const ConnKey& k) const noexcept {
        std::size_t h1 = std::hash<UINT32>{}(k.localAddr);
        std::size_t h2 = std::hash<UINT32>{}(k.remoteAddr);
        std::size_t h3 = std::hash<UINT16>{}(k.localPort);
        std::size_t h4 = std::hash<UINT16>{}(k.remotePort);
        std::size_t h5 = std::hash<UINT8>{}(k.protocol);
        return (((h1 ^ (h2 << 1)) ^ (h3 << 1)) ^ (h4 << 1)) ^ (h5 << 1);
    }
};

struct TrafficCounters {
    unsigned long long upload = 0;
    unsigned long long download = 0;
};

struct RateLimit {
    double maxKBps = 0.0;   // Zielrate (z.B. 50 KB/s)
    double tokens = 0.0;    // aktuelles Token-Guthaben in Bytes
    std::chrono::steady_clock::time_point lastUpdate;
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
    double minKBps = 0.0;   // garantierte Rate
    double maxKBps = 0.0;   // Kappe für Token Bucket
};

// Vorwärtsdeklaration TrafficMonitor für Socket-Handling
class TrafficMonitor;

// ------------------------------------------------------------
// Globale Variablen für Socket-Kommunikation
// ------------------------------------------------------------

static SOCKET g_clientSocket = INVALID_SOCKET;
static std::mutex g_clientMutex;
static std::atomic_bool g_running(true);
static TrafficMonitor* g_monitor = nullptr;

// Vorwärtsdeklaration
void HandleJsonCommand(const std::string& line);

// Hilfsfunktion: FILETIME -> 64-bit (100ns-Einheiten)
static unsigned long long FileTimeToUInt64(const FILETIME& ft) {
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return li.QuadPart;
}

// Globale Netzwerkbytes (alle Interfaces) über alte API GetIfTable
NetStats GetTotalNetworkBytes() {
    NetStats stats{ 0, 0 };

    DWORD dwSize = 0;
    if (GetIfTable(nullptr, &dwSize, FALSE) != ERROR_INSUFFICIENT_BUFFER) {
        return stats;
    }

    MIB_IFTABLE* pTable = (MIB_IFTABLE*)malloc(dwSize);
    if (!pTable) {
        return stats;
    }

    if (GetIfTable(pTable, &dwSize, FALSE) != NO_ERROR) {
        free(pTable);
        return stats;
    }

    for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
        MIB_IFROW& row = pTable->table[i];
        stats.inBytes += row.dwInOctets;
        stats.outBytes += row.dwOutOctets;
    }

    free(pTable);
    return stats;
}

std::wstring TcpStateToString(DWORD state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED:      return L"CLOSED";
    case MIB_TCP_STATE_LISTEN:      return L"LISTEN";
    case MIB_TCP_STATE_SYN_SENT:    return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:    return L"SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:       return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:   return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:   return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:  return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:     return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK:    return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:   return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:  return L"DELETE_TCB";
    default:                        return L"UNKNOWN";
    }
}

// ------------------------------------------------------------
// Socket-Hilfsfunktionen
// ------------------------------------------------------------

void SendJsonLine(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_clientMutex);
    if (g_clientSocket == INVALID_SOCKET) return;
    std::string msg = line + "\n";
    send(g_clientSocket, msg.c_str(), (int)msg.size(), 0);
}

void HandleClientCommands(SOCKET client) {
    char buffer[4096];
    std::string pending;

    while (true) {
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        pending.append(buffer, n);

        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty()) {
                HandleJsonCommand(line);
            }
        }
    }

    closesocket(client);
    {
        std::lock_guard<std::mutex> lock(g_clientMutex);
        if (g_clientSocket == client) {
            g_clientSocket = INVALID_SOCKET;
        }
    }
    std::cout << "GUI getrennt\n";
}

void ServerThreadFunc() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        std::cerr << "socket() failed\n";
        WSACleanup();
        return;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = htons(5555);

    if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "bind() failed\n";
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    if (listen(listenSock, 1) == SOCKET_ERROR) {
        std::cerr << "listen() failed\n";
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    std::cout << "TCP-Server lauscht auf 127.0.0.1:5555 (GUI-Client)...\n";

    while (g_running) {
        SOCKET client = accept(listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (!g_running) break;
            std::cerr << "accept() failed\n";
            break;
        }

        {
            std::lock_guard<std::mutex> lock(g_clientMutex);
            g_clientSocket = client;
        }
        std::cout << "GUI verbunden\n";

        std::thread recvThread(HandleClientCommands, client);
        recvThread.detach();
    }

    closesocket(listenSock);
    WSACleanup();
}

// ------------------------------------------------------------
// Prozess-/TCP-Hilfen
// ------------------------------------------------------------

void ListTcpConnectionsByProcess(const std::unordered_map<DWORD, std::wstring>& pidToName) {
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        std::wcerr << L"GetExtendedTcpTable (size) failed\n";
        return;
    }

    PMIB_TCPTABLE_OWNER_PID pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!pTable) {
        std::wcerr << L"malloc failed\n";
        return;
    }

    if (GetExtendedTcpTable(pTable, &size, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        std::wcerr << L"GetExtendedTcpTable failed\n";
        free(pTable);
        return;
    }

    std::wcout << L"\nVerbindungen (TCP, IPv4) nach Prozess:\n\n";

    for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID& row = pTable->table[i];
        DWORD pid = row.dwOwningPid;

        auto itName = pidToName.find(pid);
        std::wstring pname = (itName != pidToName.end())
            ? itName->second
            : L"<unknown>";

        sockaddr_in localAddr{};
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.S_un.S_addr = row.dwLocalAddr;
        USHORT localPort = ntohs((u_short)row.dwLocalPort);

        wchar_t localIp[64];
        InetNtopW(AF_INET, &localAddr.sin_addr, localIp, 64);

        sockaddr_in remoteAddr{};
        remoteAddr.sin_family = AF_INET;
        remoteAddr.sin_addr.S_un.S_addr = row.dwRemoteAddr;
        USHORT remotePort = ntohs((u_short)row.dwRemotePort);

        wchar_t remoteIp[64];
        InetNtopW(AF_INET, &remoteAddr.sin_addr, remoteIp, 64);

        std::wstring state = TcpStateToString(row.dwState);

        std::wcout << L"PID: " << pid
            << L" | Proc: " << pname
            << L" | " << localIp << L":" << localPort
            << L" -> " << remoteIp << L":" << remotePort
            << L" | State: " << state
            << std::endl;
    }

    free(pTable);
}

std::unordered_map<DWORD, std::wstring> BuildPidNameMap() {
    std::unordered_map<DWORD, std::wstring> pidToName;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pidToName;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        CloseHandle(hSnapshot);
        return pidToName;
    }

    do {
        pidToName[pe.th32ProcessID] = pe.szExeFile;
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return pidToName;
}

// Mapping TCP/UDP-Verbindung -> PID
bool BuildConnectionPidMap(
    std::unordered_map<ConnKey, DWORD, ConnKeyHash>& connToPid)
{
    connToPid.clear();

    auto insertConn = [&connToPid](const ConnKey& key, DWORD pid) {
        connToPid[key] = pid;
        };

    // --- TCP ---
    {
        DWORD size = 0;
        DWORD result = GetExtendedTcpTable(
            nullptr,
            &size,
            TRUE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0
        );

        if (result != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "GetExtendedTcpTable (size) failed: " << result << "\n";
            return false;
        }

        PMIB_TCPTABLE_OWNER_PID pTable =
            (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (!pTable) {
            std::cerr << "malloc failed\n";
            return false;
        }

        result = GetExtendedTcpTable(
            pTable,
            &size,
            TRUE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0
        );

        if (result != NO_ERROR) {
            std::cerr << "GetExtendedTcpTable failed: " << result << "\n";
            free(pTable);
            return false;
        }

        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            const MIB_TCPROW_OWNER_PID& row = pTable->table[i];

            ConnKey key{};
            key.localAddr = row.dwLocalAddr;
            key.remoteAddr = row.dwRemoteAddr;
            key.localPort = ntohs((u_short)row.dwLocalPort);
            key.remotePort = ntohs((u_short)row.dwRemotePort);
            key.protocol = IPPROTO_TCP;

            insertConn(key, row.dwOwningPid);
        }

        free(pTable);
    }

    // --- UDP ---
    {
        DWORD size = 0;
        DWORD result = GetExtendedUdpTable(
            nullptr,
            &size,
            TRUE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0
        );

        if (result != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "GetExtendedUdpTable (size) failed: " << result << "\n";
            return false;
        }

        PMIB_UDPTABLE_OWNER_PID pTable =
            (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (!pTable) {
            std::cerr << "malloc failed\n";
            return false;
        }

        result = GetExtendedUdpTable(
            pTable,
            &size,
            TRUE,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0
        );

        if (result != NO_ERROR) {
            std::cerr << "GetExtendedUdpTable failed: " << result << "\n";
            free(pTable);
            return false;
        }

        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            const MIB_UDPROW_OWNER_PID& row = pTable->table[i];

            ConnKey key{};
            key.localAddr = row.dwLocalAddr;
            key.remoteAddr = 0;
            key.localPort = ntohs((u_short)row.dwLocalPort);
            key.remotePort = 0;
            key.protocol = IPPROTO_UDP;

            insertConn(key, row.dwOwningPid);
        }

        free(pTable);
    }

    return true;
}

// ------------------------------------------------------------
// Optional: Task-Manager-artige Übersicht (unverändert)
// ------------------------------------------------------------

int calculateTaskManagerState()
{
    std::wcout << L"NetPrio Test gestartet...\n\n";

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const int numCpus = static_cast<int>(sysInfo.dwNumberOfProcessors);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Snapshot failed\n";
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe)) {
        std::cerr << "Process32First failed\n";
        CloseHandle(hSnapshot);
        return 1;
    }

    std::vector<ProcessInfo> processes;

    do {
        ProcessInfo p;
        p.pid = pe.th32ProcessID;
        p.name = pe.szExeFile;
        processes.push_back(p);
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    std::sort(processes.begin(), processes.end(),
        [](const ProcessInfo& a, const ProcessInfo& b) {
            return a.pid < b.pid;
        });

    std::unordered_map<DWORD, std::wstring> pidToName;
    for (const auto& p : processes) {
        pidToName[p.pid] = p.name;
    }

    std::unordered_map<DWORD, unsigned long long> cpuTimesStart;

    for (const auto& p : processes) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (!hProc) continue;

        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            unsigned long long tKernel = FileTimeToUInt64(ftKernel);
            unsigned long long tUser = FileTimeToUInt64(ftUser);
            cpuTimesStart[p.pid] = tKernel + tUser;
        }

        CloseHandle(hProc);
    }

    NetStats netStart = GetTotalNetworkBytes();
    Sleep(1000);
    NetStats netEnd = GetTotalNetworkBytes();

    for (auto& p : processes) {
        auto it = cpuTimesStart.find(p.pid);
        if (it == cpuTimesStart.end()) continue;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
        if (!hProc) continue;

        FILETIME ftCreate, ftExit, ftKernel, ftUser;
        if (GetProcessTimes(hProc, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
            unsigned long long tKernel = FileTimeToUInt64(ftKernel);
            unsigned long long tUser = FileTimeToUInt64(ftUser);
            unsigned long long cpuNow = tKernel + tUser;
            unsigned long long cpuPrev = it->second;

            unsigned long long delta = cpuNow - cpuPrev;

            const double intervalSeconds = 1.0;
            const double ticksPerSecond = 10'000'000.0;

            double cpu = (delta / (ticksPerSecond * intervalSeconds * numCpus)) * 100.0;
            p.cpuPercent = cpu;
        }

        CloseHandle(hProc);
    }

    std::wcout << std::fixed << std::setprecision(1);
    std::wcout << L"PID- / Prozessliste mit CPU-Last (% über ~1s):\n\n";

    for (const auto& p : processes) {
        std::wcout << L"PID: " << p.pid
            << L" | CPU: " << p.cpuPercent << L"%"
            << L" | Name: " << p.name
            << std::endl;
    }

    unsigned long long deltaIn = netEnd.inBytes - netStart.inBytes;
    unsigned long long deltaOut = netEnd.outBytes - netStart.outBytes;

    double downKBs = deltaIn / 1024.0;
    double upKBs = deltaOut / 1024.0;

    std::wcout << L"\nGlobale Netzwerk-Last ueber ~1s:\n";
    std::wcout << L"Download: " << downKBs << L" KB/s\n";
    std::wcout << L"Upload:   " << upKBs << L" KB/s\n";

    ListTcpConnectionsByProcess(pidToName);

    system("pause");
    return 0;
}

// ------------------------------------------------------------
// TrafficMonitor-Klasse
// ------------------------------------------------------------

class TrafficMonitor
{
public:
    TrafficMonitor()
        : handle_(INVALID_HANDLE_VALUE),
        lastPrint_(std::chrono::steady_clock::now())
    {
        priorityProfiles_[PriorityLevel::High] = { 500.0, 500.0 };
        priorityProfiles_[PriorityLevel::Medium] = { 300.0, 300.0 };
        priorityProfiles_[PriorityLevel::Low] = { 100.0, 100.0 };

        priorityOrder_ = { PriorityLevel::High,
                           PriorityLevel::Medium,
                           PriorityLevel::Low,
                           PriorityLevel::Unspecified };

        // Bucket für jede Stufe
        for (auto& [level, profile] : priorityProfiles_) {
            RateLimit& bucket = priorityBuckets_[level];
            bucket.maxKBps = profile.maxKBps;
            bucket.tokens = 0.0;
            bucket.lastUpdate = std::chrono::steady_clock::now();
        }

        // Unspecified
        RateLimit& unspecifiedBucket = priorityBuckets_[PriorityLevel::Unspecified];
        unspecifiedBucket.maxKBps = 10'000.0;
        unspecifiedBucket.tokens = 0.0;
        unspecifiedBucket.lastUpdate = std::chrono::steady_clock::now();
    }

    ~TrafficMonitor() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
        }
    }

    bool Init() {
        if (!BuildConnectionPidMap(connToPid_)) {
            std::cerr << "Konnte Connection-PID-Map nicht erstellen.\n";
            return false;
        }

        pidToName_ = BuildPidNameMap();

        handle_ = WinDivertOpen(
            "ip and (tcp or udp)",
            WINDIVERT_LAYER_NETWORK,
            0,
            0
        );
        if (handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "WinDivertOpen failed: " << GetLastError() << "\n";
            return false;
        }

        std::cout << "Connection-PID-Map aufgebaut: "
            << connToPid_.size() << " Verbindungen (TCP+UDP).\n";

        lastPrint_ = std::chrono::steady_clock::now();
        return true;
    }

    void Run() {
        const UINT MAX_PACKET = 0xFFFF;
        char packet[MAX_PACKET];
        WINDIVERT_ADDRESS addr;

        while (true) {
            UINT recvLen = 0;
            if (!WinDivertRecv(handle_, packet, sizeof(packet), &recvLen, &addr)) {
                std::cerr << "WinDivertRecv failed: " << GetLastError() << "\n";
                continue;
            }

            bool allow = ProcessPacket(packet, recvLen, addr);

            if (allow) {
                if (!WinDivertSend(handle_, packet, recvLen, nullptr, &addr)) {
                    std::cerr << "WinDivertSend failed: " << GetLastError() << "\n";
                }
            }

            PrintStatsIfIntervalElapsed();
        }
    }

    void SetLimit(DWORD pid, double maxKBps) {
        RateLimit& rl = limits_[pid];
        rl.maxKBps = maxKBps;
        rl.tokens = 0.0;
        rl.lastUpdate = std::chrono::steady_clock::now();
    }

    void SetPriorityProfile(PriorityLevel level, double minKBps, double maxKBps)
    {
        priorityProfiles_[level] = { minKBps, maxKBps };

        RateLimit& bucket = priorityBuckets_[level];
        bucket.maxKBps = maxKBps;
        bucket.tokens = 0.0;
        bucket.lastUpdate = std::chrono::steady_clock::now();

        // bereits gesetzte PIDs dieser Stufe aktualisieren
        for (const auto& [pid, prio] : pidPriority_) {
            if (prio == level) {
                ApplyPriorityLimit(pid, prio);
            }
        }
    }

    // wird direkt von der GUI über SET_PRIORITIES angesteuert
    void SetPriority(DWORD pid, PriorityLevel level)
    {
        pidPriority_[pid] = level;
        ApplyPriorityLimit(pid, level);
        std::cout << "SetPriority: PID=" << pid
            << " Level=" << static_cast<int>(level) << "\n";
    }

private:
    HANDLE handle_;
    std::unordered_map<ConnKey, DWORD, ConnKeyHash> connToPid_;
    std::unordered_map<DWORD, TrafficCounters>      traffic_;
    std::unordered_map<DWORD, std::wstring>         pidToName_;
    std::unordered_map<DWORD, RateLimit>            limits_;
    std::unordered_map<DWORD, PriorityLevel>        pidPriority_;
    std::unordered_map<PriorityLevel, RateLimit>    priorityBuckets_;
    std::unordered_map<PriorityLevel, PriorityProfile> priorityProfiles_;
    std::vector<PriorityLevel>                      priorityOrder_;
    std::chrono::steady_clock::time_point           lastPrint_;

    void ApplyPriorityLimit(DWORD pid, PriorityLevel level)
    {
        auto it = priorityProfiles_.find(level);
        if (it == priorityProfiles_.end()) {
            return;
        }
        const PriorityProfile& profile = it->second;
        SetLimit(pid, profile.maxKBps);
    }

    PriorityLevel GetPriorityForPid(DWORD pid) const
    {
        auto it = pidPriority_.find(pid);
        if (it != pidPriority_.end()) {
            return it->second;
        }
        return PriorityLevel::Unspecified;
    }

    void RefreshPriorityBucket(PriorityLevel level)
    {
        RateLimit& bucket = priorityBuckets_[level];
        auto now = std::chrono::steady_clock::now();
        if (bucket.lastUpdate.time_since_epoch().count() == 0) {
            bucket.lastUpdate = now;
        }

        double dt = std::chrono::duration<double>(now - bucket.lastUpdate).count();
        bucket.lastUpdate = now;

        double rateBytes = bucket.maxKBps * 1024.0;
        bucket.tokens += rateBytes * dt;

        double maxTokens = rateBytes;
        if (bucket.tokens > maxTokens) {
            bucket.tokens = maxTokens;
        }
    }

    bool AllowByPriority(PriorityLevel level, UINT bytes)
    {
        constexpr double kFullnessThreshold = 1.0;
        constexpr double kEpsilon = 1e-6;

        // alle Buckets refreshen
        for (PriorityLevel l : priorityOrder_) {
            RefreshPriorityBucket(l);
        }

        // solange höhere Stufen nicht "voll" sind, blocken wir niedrigere
        for (PriorityLevel l : priorityOrder_) {
            if (l == level) break;

            RateLimit& higher = priorityBuckets_[l];
            if (higher.maxKBps <= 0.0) {
                continue;
            }

            double rateBytes = higher.maxKBps * 1024.0;
            double maxTokens = rateBytes;
            double threshold = maxTokens * kFullnessThreshold;

            if (higher.tokens + kEpsilon < threshold) {
                return false;
            }
        }

        RateLimit& current = priorityBuckets_[level];
        if (current.maxKBps <= 0.0) {
            return false;
        }

        if (current.tokens >= static_cast<double>(bytes)) {
            current.tokens -= bytes;
            return true;
        }

        return false;
    }

    bool ProcessPacket(const char* packet, UINT recvLen, const WINDIVERT_ADDRESS& addr) {
        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_IPV6HDR ipv6 = nullptr;
        UINT8 protocol = 0;
        PWINDIVERT_TCPHDR tcp = nullptr;
        PWINDIVERT_UDPHDR udp = nullptr;
        PVOID data = nullptr;
        UINT dataLen = 0;

        if (!WinDivertHelperParsePacket(
            (PVOID)packet, recvLen,
            &ip, &ipv6, &protocol,
            nullptr, nullptr,
            &tcp, &udp,
            &data, &dataLen,
            nullptr, nullptr)) {
            return true;
        }

        const bool isTcp = (protocol == IPPROTO_TCP);
        const bool isUdp = (protocol == IPPROTO_UDP);

        if (!ip || (!isTcp && !isUdp))
            return true;
        if (isTcp && !tcp)
            return true;
        if (isUdp && !udp)
            return true;

        ConnKey key{};
        if (addr.Outbound) {
            key.localAddr = ip->SrcAddr;
            key.remoteAddr = ip->DstAddr;
            key.localPort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
            key.remotePort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
        }
        else {
            key.localAddr = ip->DstAddr;
            key.remoteAddr = ip->SrcAddr;
            key.localPort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
            key.remotePort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
        }
        key.protocol = isTcp ? IPPROTO_TCP : IPPROTO_UDP;

        auto it = connToPid_.find(key);

        // Fallback: UDP ohne Remote
        if (it == connToPid_.end() && protocol == IPPROTO_UDP) {
            ConnKey udpLocalOnly = key;
            udpLocalOnly.remoteAddr = 0;
            udpLocalOnly.remotePort = 0;
            it = connToPid_.find(udpLocalOnly);
        }

        if (it == connToPid_.end()) {
            return true;
        }

        DWORD pid = it->second;

        PriorityLevel level = GetPriorityForPid(pid);

        if (addr.Outbound)
            traffic_[pid].upload += recvLen;
        else
            traffic_[pid].download += recvLen;

        // 1) Prioritätskette
        if (!AllowByPriority(level, recvLen)) {
            return false;
        }

        // 2) per-PID-Limit (Token-Bucket)
        auto limIt = limits_.find(pid);
        if (limIt == limits_.end()) {
            return true; // kein Limit, nur über Prioritäts-Bucket begrenzt
        }

        RateLimit& rl = limIt->second;
        if (rl.maxKBps <= 0.0) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - rl.lastUpdate).count();
        rl.lastUpdate = now;

        double rateBytes = rl.maxKBps * 1024.0;
        rl.tokens += rateBytes * dt;

        double maxTokens = rateBytes;
        if (rl.tokens > maxTokens)
            rl.tokens = maxTokens;

        if (rl.tokens >= (double)recvLen) {
            rl.tokens -= recvLen;
            return true;
        }

        return false;
    }

    void PrintStatsIfIntervalElapsed() {
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> diff = now - lastPrint_;
        if (diff.count() < 1.0) // hier kannst du auf 0.5 runtergehen, wenn du willst
            return;

        double seconds = diff.count();

        // JSON-Objekt mit STATS
        json j;
        j["type"] = "STATS";
        j["interval_ms"] = (int)(seconds * 1000);
        j["processes"] = json::array();

        for (const auto& [pid, stats] : traffic_) {
            double downKBs = (stats.download / 1024.0) / seconds;
            double upKBs = (stats.upload / 1024.0) / seconds;

            std::string name = "<unknown>";
            auto itName = pidToName_.find(pid);
            if (itName != pidToName_.end()) {
                const std::wstring& w = itName->second;
                name.assign(w.begin(), w.end());
            }

            PriorityLevel level = GetPriorityForPid(pid);

            j["processes"].push_back({
                {"pid",        pid},
                {"name",       name},
                {"prio",       (int)level},
                {"down_kbps",  downKBs},
                {"up_kbps",    upKBs}
                });
        }

        // an GUI schicken
        SendJsonLine(j.dump());

        traffic_.clear();
        lastPrint_ = now;

        // aktuelle Maps neu aufbauen
        BuildConnectionPidMap(connToPid_);
        pidToName_ = BuildPidNameMap();
    }
};

// ------------------------------------------------------------
// JSON-Kommandos aus Python verarbeiten
// ------------------------------------------------------------

void HandleJsonCommand(const std::string& line) {
    if (!g_monitor) return;

    json j = json::parse(line, nullptr, false);
    if (j.is_discarded()) {
        std::cerr << "JSON parse error\n";
        return;
    }

    std::string type = j.value("type", "");
    if (type == "SET_PROFILES") {
        auto profs = j["profiles"];
        double highMax = profs["high"].value("max_kbps", 60000.0);
        double medMax = profs["medium"].value("max_kbps", 30000.0);
        double lowMax = profs["low"].value("max_kbps", 10000.0);

        g_monitor->SetPriorityProfile(PriorityLevel::High, 0.0, highMax);
        g_monitor->SetPriorityProfile(PriorityLevel::Medium, 0.0, medMax);
        g_monitor->SetPriorityProfile(PriorityLevel::Low, 0.0, lowMax);

        std::cout << "SET_PROFILES empfangen\n";
    }
    else if (type == "SET_PRIORITIES") {
        for (auto& item : j["priorities"]) {
            DWORD pid = item.value("pid", 0u);
            int   lvlInt = item.value("level", 99);
            PriorityLevel lvl = (PriorityLevel)lvlInt;
            g_monitor->SetPriority(pid, lvl);
        }
        std::cout << "SET_PRIORITIES empfangen\n";
    }
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main() {
    // optional: calculateTaskManagerState();

    // Server-Thread starten (für GUI)
    std::thread serverThread(ServerThreadFunc);

    TrafficMonitor monitor;
    g_monitor = &monitor;

    if (!monitor.Init()) {
        g_running = false;
        if (serverThread.joinable())
            serverThread.join();
        return 1;
    }

    // Default-Profile (werden später von der GUI überschrieben)
    monitor.SetPriorityProfile(PriorityLevel::High, 0.0, 60000.0);
    monitor.SetPriorityProfile(PriorityLevel::Medium, 0.0, 30000.0);
    monitor.SetPriorityProfile(PriorityLevel::Low, 0.0, 10000.0);

    // Monitor läuft (blockiert)
    monitor.Run();

    g_running = false;
    if (serverThread.joinable())
        serverThread.join();

    return 0;
}
