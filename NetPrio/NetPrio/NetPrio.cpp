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

    std::wcout << L"\nTCP-Verbindungen (IPv4) nach Prozess:\n\n";

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

// Mapping TCP-Verbindung -> PID
bool BuildTcpConnectionPidMap(
    std::unordered_map<ConnKey, DWORD, ConnKeyHash>& connToPid)
{
    connToPid.clear();

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

        connToPid[key] = row.dwOwningPid;
    }

    free(pTable);
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
    {}

    ~TrafficMonitor() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(handle_);
        }
    }

    bool Init() {
        if (!BuildTcpConnectionPidMap(connToPid_)) {
            std::cerr << "Konnte Connection-PID-Map nicht erstellen.\n";
            return false;
        }

        pidToName_ = BuildPidNameMap();

        handle_ = WinDivertOpen(
            "ip and tcp",                  // Filter: alle TCP IPv4 Pakete
            WINDIVERT_LAYER_NETWORK,
            0,                             // Priority
            0           // originaler Traffic geht normal weiter ,vorher WINDIVERT_FLAG_SNIFF jetzt 0
        );
        if (handle_ == INVALID_HANDLE_VALUE) {
            std::cerr << "WinDivertOpen failed: " << GetLastError() << "\n";
            return false;
        }

        std::cout << "Connection-PID-Map aufgebaut: "
            << connToPid_.size() << " TCP-Verbindungen.\n";

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

private:
    HANDLE handle_;
    std::unordered_map<ConnKey, DWORD, ConnKeyHash> connToPid_;
    std::unordered_map<DWORD, TrafficCounters>      traffic_;
    std::unordered_map<DWORD, std::wstring>         pidToName_;
    std::unordered_map<DWORD, RateLimit>            limits_;
    std::chrono::steady_clock::time_point           lastPrint_;
   
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

        // Wir wollen nur IPv4 + TCP limitieren
        if (!ip || !tcp || protocol != IPPROTO_TCP)
            return true;

        // Richtung beachten
        ConnKey key{};
        if (addr.Outbound) {
            key.localAddr = ip->SrcAddr;
            key.remoteAddr = ip->DstAddr;
            key.localPort = ntohs(tcp->SrcPort);
            key.remotePort = ntohs(tcp->DstPort);
        }
        else { // inbound
            key.localAddr = ip->DstAddr;
            key.remoteAddr = ip->SrcAddr;
            key.localPort = ntohs(tcp->DstPort);
            key.remotePort = ntohs(tcp->SrcPort);
        }
        key.protocol = IPPROTO_TCP;

        auto it = connToPid_.find(key);
        if (it == connToPid_.end()) {
            // keine Zuordnung -> nicht limitieren
            return true;
        }

        DWORD pid = it->second;

        // Statistiken (wie bisher)
        if (addr.Outbound)
            traffic_[pid].upload += recvLen;
        else
            traffic_[pid].download += recvLen;

        // --- Rate-Limit prüfen ---
        auto limIt = limits_.find(pid);
        if (limIt == limits_.end()) {
            // kein Limit gesetzt -> alles durchlassen
            return true;
        }

        RateLimit& rl = limIt->second;
        if (rl.maxKBps <= 0.0) {
            // 0 oder negativ -> komplett blocken
            return false; // Paket droppen
        }

        // Token-Bucket updaten
        auto now = std::chrono::steady_clock::now();
        double dt = std::chrono::duration<double>(now - rl.lastUpdate).count();
        rl.lastUpdate = now;

        // Rate in Bytes/s
        double rateBytes = rl.maxKBps * 1024.0;
        rl.tokens += rateBytes * dt;

        // Optional: Burst-Begrenzung, z.B. 1 Sekunde Puffer
        double maxTokens = rateBytes;
        if (rl.tokens > maxTokens)
            rl.tokens = maxTokens;

        // Reicht das Guthaben für dieses Paket?
        if (rl.tokens >= (double)recvLen) {
            rl.tokens -= recvLen;
            return true;   // senden
        }
        else {
            // Limit erreicht: Paket droppen
            return false;
        }
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

            std::cout << "PID " << pid
                << " (" << name << ") "
                << "| Download: " << downKB << " KB/s"
                << " | Upload: " << upKB << " KB/s"
                << std::endl;
        }

        traffic_.clear();
        lastPrint_ = now;

        // Map gelegentlich aktualisieren (für neue Verbindungen / Prozesse)
        BuildTcpConnectionPidMap(connToPid_);
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
    //monitor.SetLimit(5876, 50.0);

    monitor.Run();
    return 0;
}
