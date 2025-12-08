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

#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "windivert.h"

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

// ------------------------------------------------------------
// Hilfsfunktionen (CPU / globales Netzwerk / TCP-States)
// ------------------------------------------------------------

// FILETIME -> 64-bit (100ns-Einheiten)
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

        // Loopback könnte man rausfiltern, wenn man will:
        // if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

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
// Prozess-/TCP-Hilfen (Task-Manager-artige Funktionen)
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
            TRUE,                        // sortiert
            AF_INET,                     // IPv4
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
            key.localAddr = row.dwLocalAddr;      // schon in Network-Order
            key.remoteAddr = row.dwRemoteAddr;
            key.localPort = ntohs((u_short)row.dwLocalPort);
            key.remotePort = ntohs((u_short)row.dwRemotePort);
            key.protocol = IPPROTO_TCP;

            insertConn(key, row.dwOwningPid);
        }

        free(pTable);
    }

    // --- UDP (für QUIC / Streaming wichtig) ---
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
            key.remoteAddr = 0; // UDP-Tabelle enthält keine Remote-Daten
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
// Optional: Task-Manager-artige CPU/Netzwerk-Übersicht
// (du kannst das bei Bedarf aus main() aufrufen)
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

            unsigned long long delta = cpuNow - cpuPrev; // 100ns-Einheiten

            const double intervalSeconds = 1.0;
            const double ticksPerSecond = 10'000'000.0; // 100ns -> 1s

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
// TrafficMonitor-Klasse (WinDivert + Traffic pro Prozess)
// ------------------------------------------------------------

class TrafficMonitor
{
public:
    TrafficMonitor()
        : handle_(INVALID_HANDLE_VALUE),
        lastPrint_(std::chrono::steady_clock::now())
    {
        // Default-Profile: Stufe 1 > 2 > 3
        priorityProfiles_[PriorityLevel::High] = { 500.0, 500.0 };   // z.B. Spiele / Voice
        priorityProfiles_[PriorityLevel::Medium] = { 300.0, 300.0 }; // z.B. Browser / Meetings
        priorityProfiles_[PriorityLevel::Low] = { 100.0, 100.0 };    // Hintergrund-Services

        priorityOrder_ = { PriorityLevel::High, PriorityLevel::Medium, PriorityLevel::Low, PriorityLevel::Unspecified };

        // Default-Raten auch als Token-Buckets für die Stufen initialisieren
        for (auto& [level, profile] : priorityProfiles_) {
            RateLimit& bucket = priorityBuckets_[level];
            bucket.maxKBps = profile.maxKBps;
            bucket.tokens = 0.0;
            bucket.lastUpdate = std::chrono::steady_clock::now();
        }

        // Unassigned PIDs hängen an "Unspecified" und werden nur bedient, wenn alle Stufen voll sind
        RateLimit& unspecifiedBucket = priorityBuckets_[PriorityLevel::Unspecified];
        unspecifiedBucket.maxKBps = 10'000.0; // großzügiger Standardwert, wird durch Prioritätsgating gebremst
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
            "ip and (tcp or udp)",         // Filter: alle IP-Pakete mit TCP/UDP (inkl. QUIC)
            WINDIVERT_LAYER_NETWORK,
            0,                             // Priority
            0           // originaler Traffic geht normal weiter ,vorher WINDIVERT_FLAG_SNIFF jetzt 0
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
                // Paket wieder ins System einspeisen
                if (!WinDivertSend(handle_, packet, recvLen, nullptr, &addr)) {
                    std::cerr << "WinDivertSend failed: " << GetLastError() << "\n";
                }
            }
            else {
                // gedroppt -> nichts tun
                // (TCP wird das als Paketverlust sehen und ggf. neu senden)
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

        // Bereits gesetzte PIDs dieser Stufe direkt aktualisieren
        for (const auto& [pid, prio] : pidPriority_) {
            if (prio == level) {
                ApplyPriorityLimit(pid, prio);
            }
        }
    }

    void SetPriority(DWORD pid, PriorityLevel level)
    {
        pidPriority_[pid] = level;
        ApplyPriorityLimit(pid, level);
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

        // Aktuell nutzen wir min == max als feste Rate pro Stufe
        // (Token-Bucket garantiert den Wert, bis die Kappe erreicht ist)
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

        double maxTokens = rateBytes; // ~1s Burst
        if (bucket.tokens > maxTokens) {
            bucket.tokens = maxTokens;
        }
    }

    bool AllowByPriority(PriorityLevel level, UINT bytes)
    {
        constexpr double kFullnessThreshold = 1.0; // Höhere Stufen müssen vollständig gefüllt sein
        constexpr double kEpsilon = 1e-6;           // numerische Toleranz

        // Refresh alle Buckets nach Reihenfolge, damit Zeitdifferenzen konsistent sind
        for (PriorityLevel l : priorityOrder_) {
            RefreshPriorityBucket(l);
        }

        // Wenn eine höhere Stufe ihr Guthaben nicht (nahezu) voll hat, blocken wir
        for (PriorityLevel l : priorityOrder_) {
            if (l == level) break;

            RateLimit& higher = priorityBuckets_[l];
            if (higher.maxKBps <= 0.0) {
                continue; // Stufe deaktiviert
            }

            double rateBytes = higher.maxKBps * 1024.0;
            double maxTokens = rateBytes;
            double threshold = maxTokens * kFullnessThreshold;

            // Solange der höherpriorisierte Bucket nicht voll ist, gilt: höher zuerst bedienen
            if (higher.tokens + kEpsilon < threshold) {
                return false;
            }
        }

        RateLimit& current = priorityBuckets_[level];
        if (current.maxKBps <= 0.0) {
            return false;
        }

        if (current.tokens >= static_cast<double>(bytes)) {
            current.tokens -= bytes; // eigenes Budget verbrauchen
            return true;
        }

        return false;
    }

    bool ProcessPacket(const char* packet, UINT recvLen, const WINDIVERT_ADDRESS& addr) {
        // Packet parsen
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
            return true; // unparsbar -> einfach durchlassen
        }

        // Wir wollen IPv4 + TCP/UDP limitieren (UDP für QUIC/Streaming)
        const bool isTcp = (protocol == IPPROTO_TCP);
        const bool isUdp = (protocol == IPPROTO_UDP);

        if (!ip || (!isTcp && !isUdp))
            return true;
        if (isTcp && !tcp)
            return true;
        if (isUdp && !udp)
            return true;

        // Richtung beachten
        ConnKey key{};
        if (addr.Outbound) {
            key.localAddr = ip->SrcAddr;
            key.remoteAddr = ip->DstAddr;
            key.localPort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
            key.remotePort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
        }
        else { // inbound
            key.localAddr = ip->DstAddr;
            key.remoteAddr = ip->SrcAddr;
            key.localPort = ntohs(isTcp ? tcp->DstPort : udp->DstPort);
            key.remotePort = ntohs(isTcp ? tcp->SrcPort : udp->SrcPort);
        }
        key.protocol = isTcp ? IPPROTO_TCP : IPPROTO_UDP;

        auto it = connToPid_.find(key);

        // Fallback für UDP ohne Remote-Felder: match nur über localAddr/Port
        if (it == connToPid_.end() && protocol == IPPROTO_UDP) {
            ConnKey udpLocalOnly = key;
            udpLocalOnly.remoteAddr = 0;
            udpLocalOnly.remotePort = 0;
            it = connToPid_.find(udpLocalOnly);
        }

        if (it == connToPid_.end()) {
            // keine Zuordnung -> nicht limitieren
            return true;
        }

        DWORD pid = it->second;

        PriorityLevel level = GetPriorityForPid(pid);

        // Statistiken (wie bisher)
        if (addr.Outbound)
            traffic_[pid].upload += recvLen;
        else
            traffic_[pid].download += recvLen;

        // Zuerst Prioritätskette: niedrigere Stufen dürfen nur senden, wenn alle höheren "voll" sind
        if (!AllowByPriority(level, recvLen)) {
            return false;
        }

        // Optional: PID-spezifische Kappe (z.B. um Prozesse innerhalb einer Stufe zu begrenzen)
        auto limIt = limits_.find(pid);
        if (limIt == limits_.end()) {
            return true; // kein per-PID-Limit gesetzt
        }

        RateLimit& rl = limIt->second;
        if (rl.maxKBps <= 0.0) {
            return false; // explizit blockiert
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
        if (diff.count() < 1.0)
            return;

        std::cout << "\nTraffic in den letzten "
            << diff.count() << "s:\n";

        for (const auto& [pid, stats] : traffic_) {
            double upKB = stats.upload / 1024.0;
            double downKB = stats.download / 1024.0;

            std::string name = "<unknown>";
            auto itName = pidToName_.find(pid);
            if (itName != pidToName_.end()) {
                const std::wstring& w = itName->second;
                name.assign(w.begin(), w.end()); // einfache Konvertierung
            }

            PriorityLevel level = GetPriorityForPid(pid);
            std::string prioString = (level == PriorityLevel::Unspecified)
                ? "-"
                : "P" + std::to_string(static_cast<int>(level));

            std::cout << "PID " << pid
                << " (" << name << ") "
                << "[" << prioString << "] "
                << "| Download: " << downKB << " KB/s"
                << " | Upload: " << upKB << " KB/s"
                << std::endl;
        }

        traffic_.clear();
        lastPrint_ = now;

        // Map gelegentlich aktualisieren (für neue Verbindungen / Prozesse)
        BuildConnectionPidMap(connToPid_);
        pidToName_ = BuildPidNameMap();
    }
};

// ------------------------------------------------------------
// main
// ------------------------------------------------------------

int main() {
    // Optional: einmalige CPU/Netzwerk-Übersicht
    // calculateTaskManagerState();

    TrafficMonitor monitor;
    if (!monitor.Init()) {
        return 1;
    }

    // Beispielkonfiguration: Prioritäten und Limits
    // Stufen nach Wunsch anpassen (KB/s). Niedrigere Stufen werden nur bedient,
    // wenn alle höheren Token-Buckets voll sind (Top-Down-Hierarchie).
    monitor.SetPriorityProfile(PriorityLevel::High, 0.0, 60000.0);
    monitor.SetPriorityProfile(PriorityLevel::Medium, 0.0, 30000.0);
    monitor.SetPriorityProfile(PriorityLevel::Low, 0.0, 10000.0);

    // Konkrete PIDs zuweisen (hier Platzhalter-IDs ersetzen)
    monitor.SetPriority(12564, PriorityLevel::High);   // z.B. Spiel
    monitor.SetPriority(13100, PriorityLevel::Medium); // z.B. Browser
    // monitor.SetPriority(9012, PriorityLevel::Low);    // Hintergrund

    monitor.Run();
    return 0;
}