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
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <cmath>
#include <array>
#include <cstring>

#include "windivert.h"
#include "json.hpp" // nlohmann::json single header
using json = nlohmann::json;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------
static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out;
    out.resize((size_t)len);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len, nullptr, nullptr);
    return out;
}

static inline void SetAddrV4(std::array<uint8_t, 16>& dst, UINT32 v4)
{
    dst.fill(0);
    std::memcpy(dst.data(), &v4, sizeof(v4)); // keep as network-order value coming from headers/tables
}

static inline void SetAddrV6(std::array<uint8_t, 16>& dst, const void* v6_16bytes)
{
    std::memcpy(dst.data(), v6_16bytes, 16);
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
    UINT8 protocol = 0; // IPPROTO_TCP / IPPROTO_UDP

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
        // hash 16 bytes as two uint64 chunks
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
    double minKBps = 0.0; // reserved not fully implemented (needs queueing)
    double maxKBps = 0.0; // cap
};

// Token bucket limiter (per PID)
struct TokenBucket
{
    double maxKBps = 0.0; // rate (KB/s)
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

        // cap at 1 second burst (simple)
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
// Global socket server state
// ------------------------------------------------------------
static std::atomic_bool g_running(true);
static SOCKET g_clientSocket = INVALID_SOCKET;
static std::mutex g_clientMutex;

static void SendJsonLine(const std::string& line)
{
    std::lock_guard<std::mutex> lock(g_clientMutex);
    if (g_clientSocket == INVALID_SOCKET) return;
    std::string msg = line + "\n";
    send(g_clientSocket, msg.c_str(), (int)msg.size(), 0);
}

// ------------------------------------------------------------
// Windows process map
// ------------------------------------------------------------
static std::unordered_map<DWORD, std::wstring> BuildPidNameMap()
{
    std::unordered_map<DWORD, std::wstring> pidToName;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pidToName;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe))
    {
        CloseHandle(snap);
        return pidToName;
    }

    do
    {
        pidToName[pe.th32ProcessID] = pe.szExeFile;
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return pidToName;
}

// ------------------------------------------------------------
// Connection -> PID map (TCP + UDP) (IPv4 + IPv6)
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
                k.remoteAddr.fill(0); // wildcard
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
                // row.ucLocalAddr / row.ucRemoteAddr are 16 bytes
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
                k.remoteAddr.fill(0); // wildcard
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
            std::cerr << "GetExtendedTcpTable(AF_INET,size) failed: " << r << "\n";
            return false;
        }

        auto* pTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (!pTable) return false;

        r = GetExtendedTcpTable(pTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (r != NO_ERROR)
        {
            std::cerr << "GetExtendedTcpTable(AF_INET) failed: " << r << "\n";
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
            std::cerr << "GetExtendedUdpTable(AF_INET,size) failed: " << r << "\n";
            return false;
        }

        auto* pTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (!pTable) return false;

        r = GetExtendedUdpTable(pTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (r != NO_ERROR)
        {
            std::cerr << "GetExtendedUdpTable(AF_INET) failed: " << r << "\n";
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
            if (!pTable6) return false;

            r = GetExtendedTcpTable(pTable6, &size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
            if (r != NO_ERROR)
            {
                std::cerr << "GetExtendedTcpTable(AF_INET6) failed: " << r << "\n";
                free(pTable6);
                return false;
            }

            addTcp6(pTable6);
            free(pTable6);
        }
        else if (r != NO_ERROR)
        {
            // some systems may return NO_ERROR with size=0; ignore quietly
        }
    }

    // UDP IPv6
    {
        DWORD size = 0;
        DWORD r = GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (r == ERROR_INSUFFICIENT_BUFFER)
        {
            auto* pTable6 = (PMIB_UDP6TABLE_OWNER_PID)malloc(size);
            if (!pTable6) return false;

            r = GetExtendedUdpTable(pTable6, &size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
            if (r != NO_ERROR)
            {
                std::cerr << "GetExtendedUdpTable(AF_INET6) failed: " << r << "\n";
                free(pTable6);
                return false;
            }

            addUdp6(pTable6);
            free(pTable6);
        }
        else if (r != NO_ERROR)
        {
            // ignore quietly if unsupported
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
    bool Init()
    {
        pidToName_ = BuildPidNameMap();
        if (!BuildConnectionPidMap(connToPid_))
        {
            std::cerr << "BuildConnectionPidMap failed\n";
            return false;
        }

        // capture+inject (no SNIFF) - IPv4 + IPv6
        handle_ = WinDivertOpen("((ip or ipv6) and (tcp or udp))", WINDIVERT_LAYER_NETWORK, 0, 0);
        if (handle_ == INVALID_HANDLE_VALUE)
        {
            std::cerr << "WinDivertOpen failed: " << GetLastError() << "\n";
            return false;
        }

        // default profiles (GUI can overwrite)
        profiles_[PriorityLevel::High] = { 0.0, 10000.0 };
        profiles_[PriorityLevel::Medium] = { 0.0, 5000.0 };
        profiles_[PriorityLevel::Low] = { 0.0, 1000.0 };
        profiles_[PriorityLevel::Unspecified] = { 0.0, 1000000.0 };

        std::cout << "WinDivert ready. conn map size=" << connToPid_.size() << "\n";
        return true;
    }

    void Shutdown()
    {
        if (handle_ != INVALID_HANDLE_VALUE)
        {
            WinDivertClose(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }

    void RunCaptureLoop()
    {
        const UINT MAX_PACKET = 0xFFFF;
        std::vector<char> packet(MAX_PACKET);
        WINDIVERT_ADDRESS addr{};
        while (g_running)
        {
            UINT recvLen = 0;
            if (!WinDivertRecv(handle_, packet.data(), (UINT)packet.size(), &recvLen, &addr))
            {
                DWORD err = GetLastError();
                if (!g_running) break;
                std::cerr << "WinDivertRecv failed: " << err << "\n";
                continue;
            }

            bool allow = ProcessPacket(packet.data(), recvLen, addr);
            if (allow)
            {
                if (!WinDivertSend(handle_, packet.data(), recvLen, nullptr, &addr))
                {
                    std::cerr << "WinDivertSend failed: " << GetLastError() << "\n";
                }
            }
            // else drop
        }
    }

    // called by stats thread every interval
    void PublishStats(int intervalMs)
    {
        // snapshot traffic map (and clear) under lock
        std::unordered_map<DWORD, TrafficCounters> snapshot;
        std::unordered_map<DWORD, PriorityLevel> prioSnapshot;
        std::unordered_map<DWORD, std::wstring> nameSnapshot;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            snapshot.swap(traffic_);
            prioSnapshot = pidPriority_;
            nameSnapshot = pidToName_;
        }

        double seconds = intervalMs / 1000.0;
        if (seconds <= 0.0) seconds = 1.0;

        // Build JSON
        json j;
        j["type"] = "STATS";
        j["interval_ms"] = intervalMs;
        j["processes"] = json::array();

        // union: all pids with traffic + all pids that have priority set
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

        // refresh name/conn map occasionally
        static int tick = 0;
        tick++;
        if (tick % 2 == 0) // every ~2 seconds
        {
            std::lock_guard<std::mutex> lock(mtx_);
            pidToName_ = BuildPidNameMap();
            BuildConnectionPidMap(connToPid_);
        }
    }

    // GUI commands
    void SetPriorityProfile(PriorityLevel level, double minKBps, double maxKBps)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        profiles_[level] = { minKBps, maxKBps };

        // Update per PID buckets of this level
        for (const auto& [pid, lvl] : pidPriority_)
        {
            if (lvl == level)
            {
                pidBuckets_[pid].Reset(maxKBps);
            }
        }
    }

    void SetPriority(DWORD pid, PriorityLevel level)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        pidPriority_[pid] = level;

        // apply cap via per-pid bucket
        double cap = GetProfileMaxKBps_NoLock(level);
        pidBuckets_[pid].Reset(cap);
    }

private:
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    std::mutex mtx_;
    std::unordered_map<ConnKey, DWORD, ConnKeyHash> connToPid_;
    std::unordered_map<DWORD, std::wstring> pidToName_;
    std::unordered_map<DWORD, TrafficCounters> traffic_;
    std::unordered_map<DWORD, PriorityLevel> pidPriority_;
    std::unordered_map<PriorityLevel, PriorityProfile> profiles_;
    std::unordered_map<DWORD, TokenBucket> pidBuckets_;

private:
    double GetProfileMaxKBps_NoLock(PriorityLevel lvl) const
    {
        auto it = profiles_.find(lvl);
        if (it != profiles_.end()) return it->second.maxKBps;
        auto itU = profiles_.find(PriorityLevel::Unspecified);
        if (itU != profiles_.end()) return itU->second.maxKBps;
        return 1000000.0;
    }

    PriorityLevel GetPriority_NoLock(DWORD pid) const
    {
        auto it = pidPriority_.find(pid);
        if (it != pidPriority_.end()) return it->second;
        return PriorityLevel::Unspecified;
    }

    bool ProcessPacket(char* packet, UINT recvLen, const WINDIVERT_ADDRESS& addr)
    {
        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_IPV6HDR ipv6 = nullptr;
        UINT8 protocol = 0;
        PWINDIVERT_TCPHDR tcp = nullptr;
        PWINDIVERT_UDPHDR udp = nullptr;

        if (!WinDivertHelperParsePacket(
            packet, recvLen,
            &ip, &ipv6, &protocol,
            nullptr, nullptr,
            &tcp, &udp,
            nullptr, nullptr, nullptr, nullptr))
        {
            return true;
        }

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
            // IPv6
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

        {
            std::lock_guard<std::mutex> lock(mtx_);

            auto it = connToPid_.find(key);

            // UDP fallback: match by local only (both v4 and v6)
            if (it == connToPid_.end() && isUdp)
            {
                ConnKey localOnly = key;
                localOnly.remoteAddr.fill(0);
                localOnly.remotePort = 0;
                it = connToPid_.find(localOnly);
            }

            if (it == connToPid_.end())
            {
                // unknown mapping: allow to not break system
                return true;
            }

            DWORD pid = it->second;
            (void)GetPriority_NoLock(pid);

            // account traffic
            if (addr.Outbound) traffic_[pid].uploadBytes += recvLen;
            else traffic_[pid].downloadBytes += recvLen;

            // apply per PID token bucket if this PID has a bucket (set via priority)
            auto itB = pidBuckets_.find(pid);
            if (itB == pidBuckets_.end())
            {
                // if PID has no explicit bucket, allow (unlimited)
                return true;
            }

            // limiter lives in map -> must be used under lock
            bool ok = itB->second.AllowBytes(recvLen);
            return ok;
        }
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
        std::cerr << "JSON parse error\n";
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
        std::cout << "SET_PROFILES ok\n";
    }
    else if (type == "SET_PRIORITIES")
    {
        for (auto& item : j["priorities"])
        {
            DWORD pid = item.value("pid", 0u);
            int lvlInt = item.value("level", 99);
            PriorityLevel lvl = (PriorityLevel)lvlInt;
            g_monitor->SetPriority(pid, lvl);
        }
        std::cout << "SET_PRIORITIES ok\n";
    }
}

// ------------------------------------------------------------
// TCP server for GUI
// ------------------------------------------------------------
static void HandleClientCommands(SOCKET client)
{
    char buffer[4096];
    std::string pending;

    while (g_running)
    {
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n <= 0) break;

        pending.append(buffer, n);
        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos)
        {
            std::string line = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            if (!line.empty()) HandleJsonCommand(line);
        }
    }

    closesocket(client);
    {
        std::lock_guard<std::mutex> lock(g_clientMutex);
        if (g_clientSocket == client) g_clientSocket = INVALID_SOCKET;
    }
    std::cout << "GUI disconnected\n";
}

static void ServerThreadFunc()
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::cerr << "WSAStartup failed\n";
        return;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET)
    {
        std::cerr << "socket() failed\n";
        WSACleanup();
        return;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = htons(5555);

    if (bind(listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        std::cerr << "bind() failed\n";
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    if (listen(listenSock, 1) == SOCKET_ERROR)
    {
        std::cerr << "listen() failed\n";
        closesocket(listenSock);
        WSACleanup();
        return;
    }

    std::cout << "TCP server listening on 127.0.0.1:5555\n";

    while (g_running)
    {
        SOCKET client = accept(listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET)
        {
            if (!g_running) break;
            std::cerr << "accept() failed\n";
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(g_clientMutex);
            // replace old client if any
            if (g_clientSocket != INVALID_SOCKET)
            {
                closesocket(g_clientSocket);
            }
            g_clientSocket = client;
        }

        std::cout << "GUI connected\n";
        std::thread(HandleClientCommands, client).detach();
    }

    closesocket(listenSock);
    WSACleanup();
}

// ------------------------------------------------------------
// Stats publisher thread
// ------------------------------------------------------------
static void StatsThreadFunc()
{
    // ✅ 1 Punkt = 1 Sekunde fürs Frontend (Zeitachse)
    constexpr int intervalMs = 1000;
    while (g_running)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        if (g_monitor) g_monitor->PublishStats(intervalMs);
    }
}

// ------------------------------------------------------------
// main
// ------------------------------------------------------------
int main()
{
    // start GUI server
    std::thread serverThread(ServerThreadFunc);

    TrafficMonitor monitor;
    g_monitor = &monitor;

    if (!monitor.Init())
    {
        g_running = false;
        if (serverThread.joinable()) serverThread.join();
        return 1;
    }

    // start stats publisher
    std::thread statsThread(StatsThreadFunc);

    // capture loop (blocking)
    monitor.RunCaptureLoop();

    g_running = false;
    monitor.Shutdown();

    if (statsThread.joinable()) statsThread.join();
    if (serverThread.joinable()) serverThread.join();

    return 0;
}
