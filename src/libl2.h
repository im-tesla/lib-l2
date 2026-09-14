#pragma once

#ifdef _WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <timeapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")

#if defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
#endif

#else // macOS / Linux / POSIX

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ifaddrs.h>

#if defined(__APPLE__)
#include <net/if.h>
#include <net/if_dl.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <pthread.h>
#elif defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sched.h>
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif
#endif

#endif

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <vector>
#include <array>
#include <string>
#include <unordered_map>
#include <chrono>
#include <random>
#include <algorithm>
#include <optional>
#include <functional>

namespace l2 {

inline constexpr uint16_t ETHER_TYPE         = 0x88B7;   // IEC 61850 GOOSE
inline constexpr uint16_t FRAME_MAGIC        = 0x4C32;   // "L2" (legacy identifier)
inline constexpr size_t   MAC_LEN            = 6;
inline constexpr size_t   ETH_HDR_SIZE       = 14;       // dst(6) + src(6) + type(2)
inline constexpr size_t   NONCE_SIZE         = 12;       // ChaCha20 nonce
inline constexpr size_t   MAGIC_SIZE         = 2;
inline constexpr size_t   INNER_HDR_SIZE     = 16;       // encrypted inner header
inline constexpr size_t   CLEAR_OVERHEAD     = ETH_HDR_SIZE + MAGIC_SIZE + NONCE_SIZE; // 28
inline constexpr size_t   TOTAL_OVERHEAD     = CLEAR_OVERHEAD + INNER_HDR_SIZE;         // 44
inline constexpr size_t   MAX_ETH_FRAME      = 1500;
inline constexpr size_t   MAX_FRAG_PAYLOAD   = MAX_ETH_FRAME - TOTAL_OVERHEAD;          // 1456
inline constexpr size_t   KEY_SIZE           = 32;       // ChaCha20 key size
inline constexpr size_t   DEFAULT_MAX_PAD    = 8;        // max random padding bytes

using Mac = std::array<uint8_t, 6>;
inline constexpr Mac BROADCAST_MAC       = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
inline constexpr Mac GOOSE_MULTICAST_MAC = {0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01};

enum class MsgType : uint8_t {
    Text    = 0x01,
    Jpeg    = 0x02,
    Binary  = 0x03,
    Control = 0xFF,
};

enum class ControlCmd : uint8_t {
    DiscoveryRequest  = 0x01,
    DiscoveryResponse = 0x02,
    Ping              = 0x03,
    Pong              = 0x04,
};

struct DiscoveredPeer {
    Mac         mac{};
    std::string name;
};

// BUG-10 fix: properly validate discovery packet payload structure
inline std::string extract_node_name(const std::vector<uint8_t>& data) {
    if (data.size() >= 11) {
        uint16_t nlen = (uint16_t(data[9]) << 8) | data[10];
        if (data.size() >= 11 + nlen && nlen > 0) {
            return std::string(reinterpret_cast<const char*>(data.data() + 11), nlen);
        }
    }
    return "unknown";
}

enum class MsgFlags : uint8_t {
    None = 0x00,
};

struct ReceivedMessage {
    MsgType              type;
    std::vector<uint8_t> data;
    Mac                  sender_mac;
};

struct AdapterInfo {
    std::string name;        // pcap device name (pass to Config::adapter)
    std::string description; // human-readable adapter name
    Mac         mac;         // hardware MAC address
};

namespace platform {

#ifdef _WIN32
// Set system timer resolution to 0.5ms (500us) or 1ms
inline bool set_high_resolution_timer(bool enable = true) {
    using NtSetTimerResolution_t = LONG(NTAPI*)(ULONG, BOOLEAN, PULONG);
    static NtSetTimerResolution_t nt_set_timer = nullptr;
    static bool resolved = false;
    if (!resolved) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            nt_set_timer = (NtSetTimerResolution_t)GetProcAddress(ntdll, "NtSetTimerResolution");
        }
        resolved = true;
    }
    if (enable) {
        timeBeginPeriod(1);
        if (nt_set_timer) {
            ULONG cur = 0;
            nt_set_timer(5000 /* 500us */, TRUE, &cur);
        }
    } else {
        timeEndPeriod(1);
        if (nt_set_timer) {
            ULONG cur = 0;
            nt_set_timer(5000, FALSE, &cur);
        }
    }
    return true;
}

// Set thread & process priority for real-time operation and optionally pin to core
inline bool set_realtime_priority(bool thread_only = false, int cpu_affinity_core = -1) {
    if (!thread_only) {
        SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    if (cpu_affinity_core >= 0) {
        DWORD_PTR mask = DWORD_PTR(1) << cpu_affinity_core;
        SetThreadAffinityMask(GetCurrentThread(), mask);
        SetThreadIdealProcessor(GetCurrentThread(), DWORD(cpu_affinity_core));
    }
    return true;
}

// Enable Windows Multimedia Class Scheduler Service (MMCSS)
inline void* enable_mmcss(const char* task_name = "Pro Audio") {
    using AvSetMmThreadCharacteristicsA_t = HANDLE(WINAPI*)(LPCSTR, LPDWORD);
    using AvSetMmThreadPriority_t = BOOL(WINAPI*)(HANDLE, int);
    static HMODULE avrt = LoadLibraryA("Avrt.dll");
    if (!avrt) return nullptr;
    auto set_chars = (AvSetMmThreadCharacteristicsA_t)GetProcAddress(avrt, "AvSetMmThreadCharacteristicsA");
    auto set_prio  = (AvSetMmThreadPriority_t)GetProcAddress(avrt, "AvSetMmThreadPriority");
    if (!set_chars) return nullptr;
    DWORD task_idx = 0;
    HANDLE handle = set_chars(task_name, &task_idx);
    if (handle && set_prio) {
        set_prio(handle, 2 /* AVRT_PRIORITY_CRITICAL */);
    }
    return handle;
}

inline void disable_mmcss(void* handle) {
    if (!handle) return;
    using AvRevertMmThreadCharacteristics_t = BOOL(WINAPI*)(HANDLE);
    HMODULE avrt = GetModuleHandleA("Avrt.dll");
    if (avrt) {
        auto revert = (AvRevertMmThreadCharacteristics_t)GetProcAddress(avrt, "AvRevertMmThreadCharacteristics");
        if (revert) revert(static_cast<HANDLE>(handle));
    }
}

#elif defined(__APPLE__)

inline bool set_macos_realtime(uint32_t period_us = 1000) {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    auto us_to_mach = [&](uint64_t us) {
        return (uint32_t)(us * 1000ULL * tb.denom / tb.numer);
    };

    thread_time_constraint_policy_data_t policy{};
    policy.period      = us_to_mach(period_us);
    policy.computation = us_to_mach(period_us / 2);
    policy.constraint  = us_to_mach(period_us);
    policy.preemptible = 0;

    kern_return_t ret = thread_policy_set(
        mach_thread_self(),
        THREAD_TIME_CONSTRAINT_POLICY,
        (thread_policy_t)&policy,
        THREAD_TIME_CONSTRAINT_POLICY_COUNT
    );
    return ret == KERN_SUCCESS;
}

inline bool set_macos_qos_interactive() {
    return pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) == 0;
}

inline bool set_macos_affinity(int tag = 1) {
    thread_affinity_policy_data_t affinity{ tag };
    return thread_policy_set(
        mach_thread_self(),
        THREAD_AFFINITY_POLICY,
        (thread_policy_t)&affinity,
        THREAD_AFFINITY_POLICY_COUNT
    ) == KERN_SUCCESS;
}

#elif defined(__linux__)

inline bool set_thread_realtime(int priority = 99, int cpu_affinity_core = -1) {
    struct sched_param param{};
    param.sched_priority = priority;
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

    if (cpu_affinity_core >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_affinity_core, &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    }
    return true;
}

#endif

// RAII Latency Tuning Scoped Object
class ScopedLatencyTuning {
public:
    explicit ScopedLatencyTuning([[maybe_unused]] int cpu_affinity_core = -1) {
#ifdef _WIN32
        set_high_resolution_timer(true);
        set_realtime_priority(false, cpu_affinity_core);
        mmcss_ = enable_mmcss("Pro Audio");
#elif defined(__APPLE__)
        set_macos_qos_interactive();
        set_macos_realtime(1000);
        if (cpu_affinity_core >= 0) set_macos_affinity(cpu_affinity_core + 1);
#elif defined(__linux__)
        set_thread_realtime(99, cpu_affinity_core);
#endif
    }

    ~ScopedLatencyTuning() {
#ifdef _WIN32
        if (mmcss_) disable_mmcss(mmcss_);
        set_high_resolution_timer(false);
#endif
    }

    ScopedLatencyTuning(const ScopedLatencyTuning&) = delete;
    ScopedLatencyTuning& operator=(const ScopedLatencyTuning&) = delete;

private:
#ifdef _WIN32
    void* mmcss_ = nullptr;
#endif
};

} // namespace platform

namespace detail {

inline uint32_t load_le32(const uint8_t* p) {
    return uint32_t(p[0])        | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v);       p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24);
}

inline void write_be16(uint8_t* p, uint16_t v) {
    p[0] = uint8_t(v >> 8); p[1] = uint8_t(v);
}
inline void write_be32(uint8_t* p, uint32_t v) {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);  p[3] = uint8_t(v);
}
inline uint16_t read_be16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | p[1];
}
inline uint32_t read_be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  | p[3];
}

inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

inline void qr(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

inline void chacha20_block(const uint32_t key[8], uint32_t ctr,
                           const uint32_t nonce[3], uint8_t out[64]) {
    uint32_t s[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  // "expand 32-byte k"
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        ctr, nonce[0], nonce[1], nonce[2]
    };
    uint32_t w[16];
    std::memcpy(w, s, 64);

    for (int i = 0; i < 10; ++i) {      // 20 rounds = 10 double-rounds
        qr(w[0],w[4],w[8], w[12]); qr(w[1],w[5],w[9], w[13]);
        qr(w[2],w[6],w[10],w[14]); qr(w[3],w[7],w[11],w[15]);
        qr(w[0],w[5],w[10],w[15]); qr(w[1],w[6],w[11],w[12]);
        qr(w[2],w[7],w[8], w[13]); qr(w[3],w[4],w[9], w[14]);
    }
    for (int i = 0; i < 16; ++i)
        store_le32(out + 4 * i, w[i] + s[i]);
}

inline void chacha20_crypt(const uint8_t key[32], const uint8_t nonce[12],
                           const uint8_t* in, uint8_t* out, size_t len) {
    uint32_t k[8], n[3];
    for (int i = 0; i < 8; ++i) k[i] = load_le32(key + 4 * i);
    for (int i = 0; i < 3; ++i) n[i] = load_le32(nonce + 4 * i);

    uint8_t ks[64];
    for (uint32_t ctr = 0; len > 0; ++ctr) {
        chacha20_block(k, ctr, n, ks);
        size_t chunk = std::min(len, size_t(64));
        size_t i = 0;
        // Fast 64-bit XOR acceleration
        for (; i + 8 <= chunk; i += 8) {
            uint64_t in64, ks64;
            std::memcpy(&in64, in + i, 8);
            std::memcpy(&ks64, ks + i, 8);
            uint64_t out64 = in64 ^ ks64;
            std::memcpy(out + i, &out64, 8);
        }
        for (; i < chunk; ++i)
            out[i] = in[i] ^ ks[i];
        in  += chunk;
        out += chunk;
        len -= chunk;
    }
}

inline uint32_t fnv1a(const uint8_t* data, size_t len) {
    uint32_t h = 0x811C9DC5u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x01000193u;
    }
    return h;
}

inline std::string extract_guid(const std::string& s) {
    auto a = s.find('{');
    auto b = s.find('}', a != std::string::npos ? a : 0);
    if (a != std::string::npos && b != std::string::npos)
        return s.substr(a + 1, b - a - 1);
    return s;
}

inline uint16_t get_key_appid(const uint8_t key[KEY_SIZE]) {
    uint32_t h = fnv1a(key, KEY_SIZE);
    uint16_t id = uint16_t(h & 0x3FFF);
    return id == 0 ? 0x0001 : id;
}

inline Mac get_key_multicast_mac(const uint8_t key[KEY_SIZE]) {
    uint32_t h = fnv1a(key, KEY_SIZE);
    uint16_t offset = uint16_t(h & 0x01FF);
    return Mac{0x01, 0x0C, 0xCD, 0x01, uint8_t(offset >> 8), uint8_t(offset & 0xFF)};
}

} // namespace detail

namespace pcap {

struct pcap_if_t {
    pcap_if_t*  next;
    char*       name;
    char*       description;
    void*       addresses;    // pcap_addr* — unused
    uint32_t    flags;
};

struct PktHdr {
    struct timeval ts;
    uint32_t caplen;
    uint32_t len;
};

struct BpfInsn {
    uint16_t code;
    uint8_t  jt;
    uint8_t  jf;
    uint32_t k;
};

struct BpfProgram {
    uint32_t bf_len;
    BpfInsn* bf_insns;
};

using Handle = void*;

using fn_open_live           = Handle(*)(const char*, int, int, int, char*);
using fn_findalldevs         = int(*)(pcap_if_t**, char*);
using fn_freealldevs         = void(*)(pcap_if_t*);
using fn_sendpacket          = int(*)(Handle, const uint8_t*, int);
using fn_next_ex             = int(*)(Handle, PktHdr**, const uint8_t**);
using fn_close               = void(*)(Handle);
using fn_compile             = int(*)(Handle, BpfProgram*, const char*, int, uint32_t);
using fn_setfilter           = int(*)(Handle, BpfProgram*);
using fn_freecode            = void(*)(BpfProgram*);
using fn_geterr              = char*(*)(Handle);
using fn_datalink            = int(*)(Handle);
using fn_setmintocopy        = int(*)(Handle, int);
using fn_create              = Handle(*)(const char*, char*);
using fn_set_snaplen         = int(*)(Handle, int);
using fn_set_promisc         = int(*)(Handle, int);
using fn_set_timeout         = int(*)(Handle, int);
using fn_set_immediate_mode  = int(*)(Handle, int);
using fn_set_buffer_size     = int(*)(Handle, int);
using fn_activate            = int(*)(Handle);
using fn_setnonblock         = int(*)(Handle, int, char*);
using fn_get_selectable_fd   = int(*)(Handle);
using fn_sendqueue_alloc     = void*(*)(uint32_t);
using fn_sendqueue_destroy   = void(*)(void*);
using fn_sendqueue_queue     = int(*)(void*, const PktHdr*, const uint8_t*);
using fn_sendqueue_transmit  = uint32_t(*)(Handle, void*, int);

struct Library {
#ifdef _WIN32
    HMODULE           dll                   = nullptr;
#else
    void*             dll                   = nullptr;
#endif
    fn_open_live          open_live         = nullptr;
    fn_findalldevs        findalldevs       = nullptr;
    fn_freealldevs        freealldevs       = nullptr;
    fn_sendpacket         sendpacket        = nullptr;
    fn_next_ex            next_ex           = nullptr;
    fn_close              close             = nullptr;
    fn_compile            compile           = nullptr;
    fn_setfilter          setfilter         = nullptr;
    fn_freecode           freecode          = nullptr;
    fn_geterr             geterr            = nullptr;
    fn_datalink           datalink          = nullptr;
    fn_setmintocopy       setmintocopy      = nullptr;
    fn_create             create            = nullptr;
    fn_set_snaplen        set_snaplen       = nullptr;
    fn_set_promisc        set_promisc       = nullptr;
    fn_set_timeout        set_timeout       = nullptr;
    fn_set_immediate_mode set_immediate_mode= nullptr;
    fn_set_buffer_size    set_buffer_size   = nullptr;
    fn_activate           activate          = nullptr;
    fn_setnonblock        setnonblock       = nullptr;
    fn_get_selectable_fd  get_selectable_fd = nullptr;
    fn_sendqueue_alloc    sendqueue_alloc   = nullptr;
    fn_sendqueue_destroy  sendqueue_destroy = nullptr;
    fn_sendqueue_queue    sendqueue_queue   = nullptr;
    fn_sendqueue_transmit sendqueue_transmit= nullptr;
    bool                  loaded            = false;

    bool load() {
        if (loaded) return true;

#ifdef _WIN32
        char sys_dir[512]{};
        UINT len = GetSystemDirectoryA(sys_dir, sizeof(sys_dir));
        if (len > 0 && len < sizeof(sys_dir) - 16) {
            std::string npcap_dir = std::string(sys_dir) + "\\Npcap";
            SetDllDirectoryA(npcap_dir.c_str());
        }

        dll = LoadLibraryA("wpcap.dll");
        SetDllDirectoryA(nullptr);

        if (!dll) return false;

        auto get = [&](const char* n) { return GetProcAddress(dll, n); };
#else
        const char* candidates[] = {
            "libpcap.dylib",
            "/usr/lib/libpcap.dylib",
            "libpcap.A.dylib",
            "/opt/homebrew/opt/libpcap/lib/libpcap.dylib",
            "/usr/local/opt/libpcap/lib/libpcap.dylib",
            "libpcap.so",
            "libpcap.so.1",
            "/usr/lib/x86_64-linux-gnu/libpcap.so"
        };
        for (const char* c : candidates) {
            dll = dlopen(c, RTLD_LAZY);
            if (dll) break;
        }

        if (!dll) return false;

        auto get = [&](const char* n) { return dlsym(dll, n); };
#endif

        open_live          = (fn_open_live)          get("pcap_open_live");
        findalldevs        = (fn_findalldevs)        get("pcap_findalldevs");
        freealldevs        = (fn_freealldevs)        get("pcap_freealldevs");
        sendpacket         = (fn_sendpacket)         get("pcap_sendpacket");
        next_ex            = (fn_next_ex)            get("pcap_next_ex");
        close              = (fn_close)              get("pcap_close");
        compile            = (fn_compile)            get("pcap_compile");
        setfilter          = (fn_setfilter)          get("pcap_setfilter");
        freecode           = (fn_freecode)           get("pcap_freecode");
        geterr             = (fn_geterr)             get("pcap_geterr");
        datalink           = (fn_datalink)           get("pcap_datalink");
        setmintocopy       = (fn_setmintocopy)       get("pcap_setmintocopy");
        create             = (fn_create)             get("pcap_create");
        set_snaplen        = (fn_set_snaplen)        get("pcap_set_snaplen");
        set_promisc        = (fn_set_promisc)        get("pcap_set_promisc");
        set_timeout        = (fn_set_timeout)        get("pcap_set_timeout");
        set_immediate_mode = (fn_set_immediate_mode) get("pcap_set_immediate_mode");
        set_buffer_size    = (fn_set_buffer_size)    get("pcap_set_buffer_size");
        activate           = (fn_activate)           get("pcap_activate");
        setnonblock        = (fn_setnonblock)        get("pcap_setnonblock");
        get_selectable_fd  = (fn_get_selectable_fd)  get("pcap_get_selectable_fd");
        sendqueue_alloc    = (fn_sendqueue_alloc)    get("pcap_sendqueue_alloc");
        sendqueue_destroy  = (fn_sendqueue_destroy)  get("pcap_sendqueue_destroy");
        sendqueue_queue    = (fn_sendqueue_queue)    get("pcap_sendqueue_queue");
        sendqueue_transmit = (fn_sendqueue_transmit) get("pcap_sendqueue_transmit");

        loaded = (open_live || (create && activate)) && findalldevs && freealldevs &&
                 sendpacket && next_ex && close && compile && setfilter && freecode &&
                 geterr && datalink;

        if (!loaded) {
#ifdef _WIN32
            FreeLibrary(dll);
#else
            dlclose(dll);
#endif
            dll = nullptr;
        }
        return loaded;
    }

    ~Library() {
#ifdef _WIN32
        if (dll) FreeLibrary(dll);
#else
        if (dll) dlclose(dll);
#endif
    }
};

inline Library& lib() {
    static Library instance;
    return instance;
}

} // namespace pcap

inline Mac parse_mac(const std::string& str) {
    Mac m{};
    unsigned b[6]{};
    if (sscanf(str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; ++i) m[i] = uint8_t(b[i]);
    }
    return m;
}

inline std::string mac_to_string(const Mac& m) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

inline bool get_adapter_mac(const std::string& pcap_name, Mac& out) {
#ifdef _WIN32
    std::string target_guid = detail::extract_guid(pcap_name);
    if (target_guid.empty()) return false;

    ULONG buf_len = 15000;
    std::vector<uint8_t> buf(buf_len);
    auto* addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &buf_len);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(buf_len);
        addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        rc = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, addrs, &buf_len);
    }
    if (rc != NO_ERROR) return false;

    for (auto* a = addrs; a; a = a->Next) {
        if (a->PhysicalAddressLength == 6) {
            std::string adapter_guid = detail::extract_guid(a->AdapterName);
            if (_stricmp(adapter_guid.c_str(), target_guid.c_str()) == 0) {
                std::memcpy(out.data(), a->PhysicalAddress, 6);
                return true;
            }
        }
    }
    return false;
#elif defined(__APPLE__)
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0 || !ifap) return false;

    bool found = false;
    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (pcap_name == ifa->ifa_name && ifa->ifa_addr->sa_family == AF_LINK) {
            auto* sdl = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (sdl->sdl_alen == 6) {
                std::memcpy(out.data(), LLADDR(sdl), 6);
                found = true;
                break;
            }
        }
    }
    freeifaddrs(ifap);
    return found;
#elif defined(__linux__)
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, pcap_name.c_str(), sizeof(ifr.ifr_name) - 1);
    bool found = false;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0) {
        std::memcpy(out.data(), ifr.ifr_hwaddr.sa_data, 6);
        found = true;
    }
    close(fd);
    return found;
#else
    return false;
#endif
}

inline std::vector<AdapterInfo> list_adapters() {
    std::vector<AdapterInfo> result;
    if (!pcap::lib().load()) return result;

    char errbuf[256]{};
    pcap::pcap_if_t* devs = nullptr;
    if (pcap::lib().findalldevs(&devs, errbuf) != 0 || !devs)
        return result;

    for (auto* d = devs; d; d = d->next) {
        AdapterInfo info;
        info.name        = d->name        ? d->name        : "";
        info.description = d->description ? d->description : "(no description)";
        info.mac = {};
        get_adapter_mac(info.name, info.mac);
        // BUG-11 fix: always include adapters even if MAC couldn't be auto-read
        result.push_back(std::move(info));
    }

    pcap::lib().freealldevs(devs);
    return result;
}

namespace frame {

struct InnerHeader {
    uint32_t msg_id;
    uint16_t frag_idx;
    uint16_t frag_total;
    MsgType  msg_type;
    MsgFlags flags;
    uint16_t payload_len;
};

inline size_t build(const Mac& dst, const Mac& src,
                    const uint8_t key[KEY_SIZE],
                    const InnerHeader& hdr,
                    const uint8_t* payload,
                    uint8_t* out,
                    std::mt19937& rng,
                    size_t max_pad) {
    uint8_t* p = out;

    std::memcpy(p, dst.data(), 6); p += 6;
    std::memcpy(p, src.data(), 6); p += 6;
    detail::write_be16(p, ETHER_TYPE); p += 2;

    uint16_t appid = detail::get_key_appid(key);
    detail::write_be16(p, appid); p += 2;

    // BUG-4 fix: fast 32-bit words for nonce generation
    uint8_t nonce[NONCE_SIZE];
    uint32_t n0 = rng();
    uint32_t n1 = rng();
    uint32_t n2 = rng();
    std::memcpy(nonce,     &n0, 4);
    std::memcpy(nonce + 4, &n1, 4);
    std::memcpy(nonce + 8, &n2, 4);
    std::memcpy(p, nonce, NONCE_SIZE); p += NONCE_SIZE;

    // BUG-5 fix: clamp padding to prevent any buffer overflow
    size_t avail_for_pad = (MAX_FRAG_PAYLOAD > hdr.payload_len) ? (MAX_FRAG_PAYLOAD - hdr.payload_len) : 0;
    size_t pad_len = 0;
    if (max_pad > 0 && avail_for_pad > 0) {
        size_t allowed = std::min(max_pad, avail_for_pad);
        pad_len = std::uniform_int_distribution<size_t>(0, allowed)(rng);
    }

    size_t plain_len = INNER_HDR_SIZE + hdr.payload_len + pad_len;
    if (plain_len > MAX_ETH_FRAME) {
        pad_len = (MAX_ETH_FRAME > INNER_HDR_SIZE + hdr.payload_len) ? (MAX_ETH_FRAME - INNER_HDR_SIZE - hdr.payload_len) : 0;
        plain_len = INNER_HDR_SIZE + hdr.payload_len + pad_len;
    }

    uint8_t plain[MAX_ETH_FRAME];   // stack buffer (max 1500 bytes)

    uint8_t* h = plain;
    detail::write_be32(h, hdr.msg_id);          h += 4;
    detail::write_be16(h, hdr.frag_idx);        h += 2;
    detail::write_be16(h, hdr.frag_total);      h += 2;
    *h++ = uint8_t(hdr.msg_type);
    *h++ = uint8_t(hdr.flags);
    detail::write_be16(h, hdr.payload_len);     h += 2;
    uint32_t check = detail::fnv1a(plain, 12);
    detail::write_be32(h, check);               h += 4;

    if (hdr.payload_len > 0)
        std::memcpy(h, payload, hdr.payload_len);
    h += hdr.payload_len;

    // Fast word-based random padding
    size_t full_words = pad_len / 4;
    size_t rem_bytes  = pad_len % 4;
    for (size_t i = 0; i < full_words; ++i) {
        uint32_t r = rng();
        std::memcpy(h, &r, 4);
        h += 4;
    }
    if (rem_bytes > 0) {
        uint32_t r = rng();
        std::memcpy(h, &r, rem_bytes);
        h += rem_bytes;
    }

    detail::chacha20_crypt(key, nonce, plain, p, plain_len);
    p += plain_len;

    return size_t(p - out);
}

// Zero-copy parse directly into provided plain buffer (avoids intermediate std::vector)
inline bool parse(const uint8_t* frame, size_t frame_len,
                  const uint8_t key[KEY_SIZE],
                  uint16_t expected_appid,
                  Mac& sender_mac, InnerHeader& hdr,
                  const uint8_t*& payload_out,
                  uint8_t* plain_out,
                  bool allow_legacy_magic = false) {

    if (frame_len < TOTAL_OVERHEAD) return false;

    const uint8_t* p = frame;

    p += 6;  // skip dst
    std::memcpy(sender_mac.data(), p, 6); p += 6;

    if (detail::read_be16(p) != ETHER_TYPE) return false;
    p += 2;

    uint16_t frame_appid = detail::read_be16(p); p += 2;
    // BUG-6 fix: reject foreign packets strictly unless allow_legacy_magic is set
    if (frame_appid != expected_appid && (!allow_legacy_magic || frame_appid != FRAME_MAGIC)) {
        return false;
    }

    uint8_t nonce[NONCE_SIZE];
    std::memcpy(nonce, p, NONCE_SIZE); p += NONCE_SIZE;

    size_t enc_len = frame_len - CLEAR_OVERHEAD;
    if (enc_len < INNER_HDR_SIZE || enc_len > MAX_ETH_FRAME) return false;

    detail::chacha20_crypt(key, nonce, p, plain_out, enc_len);

    const uint8_t* h = plain_out;
    hdr.msg_id      = detail::read_be32(h); h += 4;
    hdr.frag_idx    = detail::read_be16(h); h += 2;
    hdr.frag_total  = detail::read_be16(h); h += 2;
    hdr.msg_type    = MsgType(*h++);
    hdr.flags       = MsgFlags(*h++);
    hdr.payload_len = detail::read_be16(h); h += 2;

    uint32_t expected_check = detail::fnv1a(plain_out, 12);
    uint32_t actual_check   = detail::read_be32(h); h += 4;
    if (expected_check != actual_check) return false;  // wrong key or corruption

    if (hdr.frag_total == 0) return false;
    if (hdr.frag_idx >= hdr.frag_total) return false;
    if (hdr.payload_len > enc_len - INNER_HDR_SIZE) return false;

    payload_out = h;
    return true;
}

// Backward-compatible parse overload with std::vector<uint8_t>&
inline bool parse(const uint8_t* frame, size_t frame_len,
                  const uint8_t key[KEY_SIZE],
                  Mac& sender_mac, InnerHeader& hdr,
                  std::vector<uint8_t>& payload_out,
                  bool allow_legacy_magic = false) {
    uint8_t plain[MAX_ETH_FRAME];
    const uint8_t* pdata = nullptr;
    uint16_t expected_appid = detail::get_key_appid(key);
    if (!parse(frame, frame_len, key, expected_appid, sender_mac, hdr, pdata, plain, allow_legacy_magic))
        return false;
    payload_out.assign(pdata, pdata + hdr.payload_len);
    return true;
}

} // namespace frame

// BUG-2 fix: Composite key of (sender_mac, msg_id) to prevent cross-sender collision
struct MessageKey {
    Mac sender{};
    uint32_t msg_id = 0;

    bool operator==(const MessageKey& o) const noexcept {
        return msg_id == o.msg_id && sender == o.sender;
    }
};

struct MessageKeyHash {
    size_t operator()(const MessageKey& k) const noexcept {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (uint8_t b : k.sender) {
            h ^= b;
            h *= 0x100000001b3ULL;
        }
        h ^= k.msg_id;
        h *= 0x100000001b3ULL;
        return size_t(h);
    }
};

class Reassembler {
public:
    // Fast path: accepts raw pointer to avoid intermediate heap allocation
    std::optional<ReceivedMessage> add(const Mac& sender,
                                       const frame::InnerHeader& hdr,
                                       const uint8_t* payload_data,
                                       size_t payload_len) {
        // Zero-lookup fast path for unfragmented (single-packet) messages
        if (hdr.frag_total == 1 && hdr.frag_idx == 0) {
            ReceivedMessage msg;
            msg.type       = hdr.msg_type;
            msg.sender_mac = sender;
            msg.data.assign(payload_data, payload_data + payload_len);
            return msg;
        }

        if (hdr.frag_total == 0 || hdr.frag_idx >= hdr.frag_total) {
            return std::nullopt;
        }

        MessageKey key{ sender, hdr.msg_id };
        auto& buf = buffers_[key];

        if (buf.fragments.empty()) {
            buf.frag_total  = hdr.frag_total;
            buf.msg_type    = hdr.msg_type;
            buf.sender_mac  = sender;
            buf.fragments.resize(hdr.frag_total);
            buf.received.resize(hdr.frag_total, false);
            buf.created     = std::chrono::steady_clock::now();
        } else {
            // BUG-3 fix: validate frag_total consistency across fragments
            if (hdr.frag_total != buf.frag_total) {
                return std::nullopt;
            }
        }

        if (hdr.frag_idx < buf.frag_total && !buf.received[hdr.frag_idx]) {
            buf.received[hdr.frag_idx] = true;
            buf.fragments[hdr.frag_idx].assign(payload_data, payload_data + payload_len);
            ++buf.count;
        }

        if (buf.count == buf.frag_total) {
            ReceivedMessage msg;
            msg.type       = buf.msg_type;
            msg.sender_mac = buf.sender_mac;

            size_t total = 0;
            for (const auto& f : buf.fragments) total += f.size();
            msg.data.reserve(total);
            for (auto& f : buf.fragments) {
                msg.data.insert(msg.data.end(), f.begin(), f.end());
            }

            buffers_.erase(key);
            return msg;
        }

        return std::nullopt;
    }

    // Overload for backward compatibility with std::vector<uint8_t>
    std::optional<ReceivedMessage> add(const Mac& sender,
                                       const frame::InnerHeader& hdr,
                                       const std::vector<uint8_t>& payload) {
        return add(sender, hdr, payload.data(), payload.size());
    }

    void purge(std::chrono::seconds max_age = std::chrono::seconds(5)) {
        if (buffers_.empty()) return;
        auto now = std::chrono::steady_clock::now();
        for (auto it = buffers_.begin(); it != buffers_.end(); ) {
            if (now - it->second.created > max_age)
                it = buffers_.erase(it);
            else
                ++it;
        }
    }

    size_t pending_count() const { return buffers_.size(); }

private:
    struct Buffer {
        uint16_t frag_total = 0;
        MsgType  msg_type   = MsgType::Binary;
        Mac      sender_mac{};
        std::vector<std::vector<uint8_t>> fragments;
        std::vector<bool> received;
        uint16_t count = 0;
        std::chrono::steady_clock::time_point created;
    };

    std::unordered_map<MessageKey, Buffer, MessageKeyHash> buffers_;
};

class L2Channel {
public:
    struct Config {
        std::string adapter;                 // pcap device name (from list_adapters)
        Mac         peer_mac{};              // destination MAC address
        uint8_t     key[KEY_SIZE]{};         // pre-shared 256-bit encryption key
        Mac         local_mac{};             // custom local MAC (empty = auto-detect)
        bool        random_mac          = false; // generate random session MAC
        bool        padding             = true;  // enable random per-frame padding
        size_t      max_pad             = DEFAULT_MAX_PAD; // max padding bytes
        int         read_timeout_ms     = 1;     // pcap read timeout (1ms or 0 for non-blocking spin)
        int         buffer_size_bytes   = 512 * 1024; // pcap ring buffer size (512KB for low latency)
        bool        auto_discovery_reply= true;  // automatically reply to discovery requests
        bool        allow_legacy_magic  = false; // accept legacy FRAME_MAGIC APPID
        std::string node_name;               // friendly name announced in discovery
        std::string custom_bpf_filter;       // optional custom BPF filter
    };

    L2Channel() = default;
    ~L2Channel() { close(); }

    L2Channel(const L2Channel&)            = delete;
    L2Channel& operator=(const L2Channel&) = delete;
    L2Channel(L2Channel&& o) noexcept      { swap(o); }
    L2Channel& operator=(L2Channel&& o) noexcept { swap(o); return *this; }

    bool open(const Config& cfg) {
        if (!pcap::lib().load()) {
#ifdef _WIN32
            last_error_ = "Failed to load Npcap (wpcap.dll). Is Npcap installed?";
#elif defined(__APPLE__)
            last_error_ = "Failed to load libpcap (libpcap.dylib). Ensure libpcap is available.";
#else
            last_error_ = "Failed to load libpcap (libpcap.so). Ensure libpcap is installed.";
#endif
            return false;
        }

        cfg_ = cfg;
        expected_appid_ = detail::get_key_appid(cfg_.key);
        key_multicast_  = detail::get_key_multicast_mac(cfg_.key);

        if (cfg_.node_name.empty()) {
#ifdef _WIN32
            char comp_name[MAX_COMPUTERNAME_LENGTH + 1]{};
            DWORD comp_size = sizeof(comp_name);
            if (GetComputerNameA(comp_name, &comp_size)) {
                cfg_.node_name = comp_name;
            } else {
                cfg_.node_name = "node";
            }
#else
            char host_buf[256]{};
            if (gethostname(host_buf, sizeof(host_buf)) == 0 && host_buf[0] != '\0') {
                cfg_.node_name = host_buf;
            } else {
                const char* user = std::getenv("USER");
                cfg_.node_name = user ? user : "node";
            }
#endif
        }

        if (cfg_.random_mac) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint32_t> d(0, 255);
            for (auto& b : local_mac_) b = uint8_t(d(gen));
            local_mac_[0] &= 0xFE;  // unicast bit
            local_mac_[0] |= 0x02;  // locally-administered bit
        } else if (cfg_.local_mac != Mac{}) {
            local_mac_ = cfg_.local_mac;
        } else {
            if (!get_adapter_mac(cfg_.adapter, local_mac_)) {
                last_error_ = "Cannot determine adapter MAC. Specify local_mac manually.";
                return false;
            }
        }

        char errbuf[256]{};

        // Ultra-low-latency activation: pcap_create + pcap_set_immediate_mode
        if (pcap::lib().create && pcap::lib().activate) {
            handle_ = pcap::lib().create(cfg_.adapter.c_str(), errbuf);
            if (handle_) {
                if (pcap::lib().set_snaplen)
                    pcap::lib().set_snaplen(handle_, MAX_ETH_FRAME + 64);
                if (pcap::lib().set_promisc)
                    pcap::lib().set_promisc(handle_, 1);
                if (pcap::lib().set_timeout)
                    pcap::lib().set_timeout(handle_, cfg_.read_timeout_ms);
                if (pcap::lib().set_immediate_mode)
                    pcap::lib().set_immediate_mode(handle_, 1); // Deliver packet immediately!
                if (pcap::lib().set_buffer_size && cfg_.buffer_size_bytes > 0)
                    pcap::lib().set_buffer_size(handle_, cfg_.buffer_size_bytes);
                if (pcap::lib().activate(handle_) < 0) {
                    pcap::lib().close(handle_);
                    handle_ = nullptr;
                }
            }
        }

        // Fallback to pcap_open_live
        if (!handle_) {
            handle_ = pcap::lib().open_live(
                cfg_.adapter.c_str(),
                MAX_ETH_FRAME + 64,       // snaplen
                1,                         // promiscuous
                cfg_.read_timeout_ms,      // read timeout (ms)
                errbuf
            );
        }

        if (!handle_) {
            last_error_ = std::string("pcap open error: ") + errbuf;
            return false;
        }

        if (pcap::lib().datalink(handle_) != 1 /* DLT_EN10MB */) {
            last_error_ = "Adapter is not Ethernet (DLT_EN10MB required)";
            pcap::lib().close(handle_);
            handle_ = nullptr;
            return false;
        }

        // Windows Npcap: zero delay threshold
        if (pcap::lib().setmintocopy)
            pcap::lib().setmintocopy(handle_, 1);

#if defined(__linux__)
        if (pcap::lib().get_selectable_fd) {
            int fd = pcap::lib().get_selectable_fd(handle_);
            if (fd >= 0) {
                int busy_poll_us = 50;
                setsockopt(fd, SOL_SOCKET, 46 /* SO_BUSY_POLL */, &busy_poll_us, sizeof(busy_poll_us));
            }
        }
#endif

        // Tight BPF filter: filter in kernel by EtherType and APPID (fewer wakeups)
        std::string filter;
        if (!cfg_.custom_bpf_filter.empty()) {
            filter = cfg_.custom_bpf_filter;
        } else {
            char filter_buf[128];
            if (cfg_.allow_legacy_magic) {
                std::snprintf(filter_buf, sizeof(filter_buf),
                    "ether[12:2] = 0x88b7 and (ether[14:2] = 0x%04x or ether[14:2] = 0x4c32)",
                    expected_appid_);
            } else {
                std::snprintf(filter_buf, sizeof(filter_buf),
                    "ether[12:2] = 0x88b7 and ether[14:2] = 0x%04x",
                    expected_appid_);
            }
            filter = filter_buf;
        }

        pcap::BpfProgram bpf{};
        if (pcap::lib().compile(handle_, &bpf, filter.c_str(), 1, 0) == 0) {
            pcap::lib().setfilter(handle_, &bpf);
            pcap::lib().freecode(&bpf);
        } else {
            // Fallback to broader EtherType filter if complex filter is rejected
            const char* fallback_filter = "ether[12:2] = 0x88b7";
            if (pcap::lib().compile(handle_, &bpf, fallback_filter, 1, 0) == 0) {
                pcap::lib().setfilter(handle_, &bpf);
                pcap::lib().freecode(&bpf);
            }
        }

        std::random_device rd;
        rng_.seed(rd());
        msg_counter_ = std::uniform_int_distribution<uint32_t>(1, UINT32_MAX / 2)(rng_);
        purge_counter_ = 0;

        open_ = true;
        return true;
    }

    void close() {
        if (handle_) {
            pcap::lib().close(handle_);
            handle_ = nullptr;
        }
        open_ = false;
    }

    bool is_open() const { return open_; }
    const Mac& local_mac() const { return local_mac_; }
    const std::string& last_error() const { return last_error_; }
    const std::string& node_name() const { return cfg_.node_name; }
    void set_node_name(const std::string& name) { cfg_.node_name = name; }
    const Mac& peer_mac() const { return cfg_.peer_mac; }
    void set_peer_mac(const Mac& mac) { cfg_.peer_mac = mac; }
    const Mac& multicast_mac() const { return key_multicast_; }

    bool send_to(const Mac& dst, const void* data, size_t len, MsgType type) {
        if (!open_) { last_error_ = "Channel not open"; return false; }

        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint32_t msg_id = msg_counter_++;

        size_t max_payload = cfg_.padding
            ? (MAX_FRAG_PAYLOAD - cfg_.max_pad)
            : MAX_FRAG_PAYLOAD;

        uint16_t frag_total = uint16_t(len > 0 ? (len + max_payload - 1) / max_payload : 1);

        uint8_t frame_buf[MAX_ETH_FRAME + 64];

        // Windows Npcap sendqueue optimization: batch all fragments into a single syscall!
        if (frag_total > 1 && pcap::lib().sendqueue_alloc && pcap::lib().sendqueue_queue && pcap::lib().sendqueue_transmit) {
            size_t queue_size = size_t(frag_total) * (MAX_ETH_FRAME + 64 + sizeof(pcap::PktHdr));
            void* q = pcap::lib().sendqueue_alloc(uint32_t(queue_size));
            if (q) {
                bool queued_all = true;
                for (uint16_t i = 0; i < frag_total; ++i) {
                    size_t offset = size_t(i) * max_payload;
                    size_t chunk  = (len > 0) ? std::min(max_payload, len - offset) : 0;

                    frame::InnerHeader hdr{};
                    hdr.msg_id      = msg_id;
                    hdr.frag_idx    = i;
                    hdr.frag_total  = frag_total;
                    hdr.msg_type    = type;
                    hdr.flags       = MsgFlags::None;
                    hdr.payload_len = uint16_t(chunk);

                    size_t frame_len = frame::build(
                        dst, local_mac_, cfg_.key,
                        hdr, bytes + offset, frame_buf, rng_,
                        cfg_.padding ? cfg_.max_pad : 0
                    );

                    pcap::PktHdr phdr{};
                    phdr.caplen = uint32_t(frame_len);
                    phdr.len    = uint32_t(frame_len);

                    if (pcap::lib().sendqueue_queue(q, &phdr, frame_buf) != 0) {
                        queued_all = false;
                        break;
                    }
                }

                if (queued_all) {
                    // sync = 0 transmits as fast as the hardware allows
                    uint32_t sent_bytes = pcap::lib().sendqueue_transmit(handle_, q, 0);
                    pcap::lib().sendqueue_destroy(q);
                    if (sent_bytes == 0) {
                        last_error_ = std::string("sendqueue_transmit failed: ") + pcap::lib().geterr(handle_);
                        return false;
                    }
                    return true;
                }
                pcap::lib().sendqueue_destroy(q);
            }
        }

        // Standard sequential packet transmission
        for (uint16_t i = 0; i < frag_total; ++i) {
            size_t offset = size_t(i) * max_payload;
            size_t chunk  = (len > 0) ? std::min(max_payload, len - offset) : 0;

            frame::InnerHeader hdr{};
            hdr.msg_id      = msg_id;
            hdr.frag_idx    = i;
            hdr.frag_total  = frag_total;
            hdr.msg_type    = type;
            hdr.flags       = MsgFlags::None;
            hdr.payload_len = uint16_t(chunk);

            size_t frame_len = frame::build(
                dst, local_mac_, cfg_.key,
                hdr, bytes + offset, frame_buf, rng_,
                cfg_.padding ? cfg_.max_pad : 0
            );

            if (pcap::lib().sendpacket(handle_, frame_buf, int(frame_len)) != 0) {
                last_error_ = std::string("sendpacket: ") + pcap::lib().geterr(handle_);
                return false;
            }
        }

        return true;
    }

    bool send(const void* data, size_t len, MsgType type) {
        return send_to(cfg_.peer_mac, data, len, type);
    }

    bool send_to(const Mac& dst, const std::string& text) {
        return send_to(dst, text.data(), text.size(), MsgType::Text);
    }

    bool send(const std::string& text) {
        return send_to(cfg_.peer_mac, text);
    }

    bool send_jpeg(const void* data, size_t len) {
        return send(data, len, MsgType::Jpeg);
    }

    bool send_binary(const void* data, size_t len) {
        return send(data, len, MsgType::Binary);
    }

    bool send_discovery_beacon(const std::string& request_name = "") {
        if (!open_) { last_error_ = "Channel not open"; return false; }

        std::string req_name = request_name.empty() ? cfg_.node_name : request_name;
        uint64_t cookie = (uint64_t(rng_()) << 32) | rng_();

        std::uniform_int_distribution<size_t> pad_dist(32, 96);
        size_t pad_len = pad_dist(rng_);

        std::vector<uint8_t> req;
        req.reserve(1 + 8 + 2 + req_name.size() + 2 + pad_len);
        req.push_back(uint8_t(ControlCmd::DiscoveryRequest));

        for (int i = 7; i >= 0; --i) req.push_back(uint8_t((cookie >> (i * 8)) & 0xFF));

        uint16_t nlen = uint16_t(req_name.size());
        req.push_back(uint8_t(nlen >> 8));
        req.push_back(uint8_t(nlen & 0xFF));
        req.insert(req.end(), req_name.begin(), req_name.end());

        req.push_back(uint8_t(pad_len >> 8));
        req.push_back(uint8_t(pad_len & 0xFF));
        for (size_t i = 0; i < pad_len; ++i) req.push_back(uint8_t(rng_() & 0xFF));

        bool ok = send_to(key_multicast_, req.data(), req.size(), MsgType::Control);
        send_to(BROADCAST_MAC, req.data(), req.size(), MsgType::Control);
        return ok;
    }

    std::vector<DiscoveredPeer> discover_peers(int timeout_ms = 1500, const std::string& request_name = "") {
        std::vector<DiscoveredPeer> peers;
        if (!open_) { last_error_ = "Channel not open"; return peers; }

        std::string req_name = request_name.empty() ? cfg_.node_name : request_name;

        // Generate 64-bit random challenge cookie for anti-replay & session uniqueness
        uint64_t cookie = (uint64_t(rng_()) << 32) | rng_();

        // Dynamic random padding (32 to 96 bytes)
        std::uniform_int_distribution<size_t> pad_dist(32, 96);
        size_t pad_len = pad_dist(rng_);

        std::vector<uint8_t> req;
        req.reserve(1 + 8 + 2 + req_name.size() + 2 + pad_len);
        req.push_back(uint8_t(ControlCmd::DiscoveryRequest));

        // 8-byte challenge cookie (big endian)
        for (int i = 7; i >= 0; --i) req.push_back(uint8_t((cookie >> (i * 8)) & 0xFF));

        // 2-byte node name length + node name
        uint16_t nlen = uint16_t(req_name.size());
        req.push_back(uint8_t(nlen >> 8));
        req.push_back(uint8_t(nlen & 0xFF));
        req.insert(req.end(), req_name.begin(), req_name.end());

        // 2-byte random padding length + padding bytes
        req.push_back(uint8_t(pad_len >> 8));
        req.push_back(uint8_t(pad_len & 0xFF));
        for (size_t i = 0; i < pad_len; ++i) req.push_back(uint8_t(rng_() & 0xFF));

        // Transmit discovery beacon to key-derived IEC 61850 GOOSE multicast address
        if (!send_to(key_multicast_, req.data(), req.size(), MsgType::Control))
            return peers;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        bool fallback_broadcast_sent = false;

        while (std::chrono::steady_clock::now() < deadline) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) break;

            // In case a switch blocks non-IP multicast, send fallback broadcast at midpoint
            if (peers.empty() && !fallback_broadcast_sent && remaining < timeout_ms / 2) {
                send_to(BROADCAST_MAC, req.data(), req.size(), MsgType::Control);
                fallback_broadcast_sent = true;
            }

            int step_timeout = int(std::min<int64_t>(remaining, 50));
            auto msg = recv(step_timeout);
            if (msg.has_value() && msg->type == MsgType::Control && !msg->data.empty()) {
                if (msg->data[0] == uint8_t(ControlCmd::DiscoveryResponse)) {
                    // BUG-9 fix: strict cookie validation (no bypass for resp_cookie == 0)
                    if (msg->data.size() >= 9) {
                        uint64_t resp_cookie = 0;
                        for (int i = 0; i < 8; ++i) {
                            resp_cookie = (resp_cookie << 8) | msg->data[1 + i];
                        }
                        if (resp_cookie != cookie) {
                            continue;
                        }
                    } else {
                        continue;
                    }

                    auto it = std::find_if(peers.begin(), peers.end(),
                        [&](const DiscoveredPeer& p) { return p.mac == msg->sender_mac; });
                    if (it == peers.end()) {
                        DiscoveredPeer p;
                        p.mac = msg->sender_mac;
                        p.name = extract_node_name(msg->data);
                        peers.push_back(std::move(p));
                    }
                }
            }
        }

        return peers;
    }

    std::optional<Mac> discover_peer(int timeout_ms = 1500) {
        auto peers = discover_peers(timeout_ms);
        if (peers.empty()) return std::nullopt;
        return peers[0].mac;
    }

    std::optional<ReceivedMessage> recv(int timeout_ms = 1) {
        if (!open_) return std::nullopt;

        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::milliseconds(timeout_ms);

        uint8_t plain_buf[MAX_ETH_FRAME];

        do {
            pcap::PktHdr* pkt_hdr    = nullptr;
            const uint8_t* pkt_data  = nullptr;

            int res = pcap::lib().next_ex(handle_, &pkt_hdr, &pkt_data);
            if (res != 1 || !pkt_data) {
                if (timeout_ms <= 0) break;
                continue;
            }

            if (pkt_hdr->caplen < TOTAL_OVERHEAD) continue;

            Mac sender{};
            frame::InnerHeader hdr{};
            const uint8_t* payload_ptr = nullptr;

            // Zero-copy parse directly into plain_buf
            if (!frame::parse(pkt_data, pkt_hdr->caplen, cfg_.key,
                              expected_appid_, sender, hdr, payload_ptr, plain_buf,
                              cfg_.allow_legacy_magic))
                continue;

            if (sender == local_mac_) continue;

            Mac dst;
            std::memcpy(dst.data(), pkt_data, 6);

            // BUG-7 fix: key_multicast_ is cached instead of computed per packet
            if (dst != local_mac_ && dst != BROADCAST_MAC &&
                dst != GOOSE_MULTICAST_MAC && dst != key_multicast_)
                continue;

            auto msg = reassembler_.add(sender, hdr, payload_ptr, hdr.payload_len);
            if (msg.has_value()) {
                if (msg->type == MsgType::Control && !msg->data.empty() &&
                    msg->data[0] == uint8_t(ControlCmd::DiscoveryRequest) &&
                    cfg_.auto_discovery_reply) {

                    uint64_t req_cookie = 0;
                    if (msg->data.size() >= 9) {
                        for (int i = 0; i < 8; ++i)
                            req_cookie = (req_cookie << 8) | msg->data[1 + i];
                    }

                    std::uniform_int_distribution<size_t> pad_dist(32, 96);
                    size_t pad_len = pad_dist(rng_);

                    std::vector<uint8_t> resp;
                    resp.reserve(1 + 8 + 2 + cfg_.node_name.size() + 2 + pad_len);
                    resp.push_back(uint8_t(ControlCmd::DiscoveryResponse));

                    for (int i = 7; i >= 0; --i)
                        resp.push_back(uint8_t((req_cookie >> (i * 8)) & 0xFF));

                    uint16_t nlen = uint16_t(cfg_.node_name.size());
                    resp.push_back(uint8_t(nlen >> 8));
                    resp.push_back(uint8_t(nlen & 0xFF));
                    resp.insert(resp.end(), cfg_.node_name.begin(), cfg_.node_name.end());

                    resp.push_back(uint8_t(pad_len >> 8));
                    resp.push_back(uint8_t(pad_len & 0xFF));
                    for (size_t i = 0; i < pad_len; ++i) resp.push_back(uint8_t(rng_() & 0xFF));

                    send_to(msg->sender_mac, resp.data(), resp.size(), MsgType::Control);
                }
                return msg;
            }

            if (++purge_counter_ % 1000 == 0)
                reassembler_.purge();

        } while (timeout_ms > 0 && std::chrono::steady_clock::now() < deadline);

        return std::nullopt;
    }

    std::optional<ReceivedMessage> try_recv() {
        return recv(0);
    }

    // BUG-8 & LAT-9 fix: template callback removes std::function virtual dispatch;
    // poll_timeout_ms defaults to 0 (non-blocking spin-polling for ultra-low latency)
    template <typename Callback>
    void recv_loop(Callback&& callback, int timeout_ms = -1, int poll_timeout_ms = 0) {
        auto start = std::chrono::steady_clock::now();
        while (open_) {
            auto msg = recv(poll_timeout_ms);
            if (msg.has_value()) {
                if (!callback(*msg)) return;
            } else if (poll_timeout_ms == 0) {
#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
#if defined(_MSC_VER)
                _mm_pause();
#else
                __builtin_ia32_pause();
#endif
#endif
            }
            if (timeout_ms >= 0) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= timeout_ms) return;
            }
        }
    }

private:
    void swap(L2Channel& o) noexcept {
        std::swap(handle_,          o.handle_);
        std::swap(cfg_,             o.cfg_);
        std::swap(local_mac_,       o.local_mac_);
        std::swap(open_,            o.open_);
        std::swap(rng_,             o.rng_);
        std::swap(last_error_,      o.last_error_);
        std::swap(reassembler_,     o.reassembler_);
        std::swap(purge_counter_,   o.purge_counter_);
        std::swap(msg_counter_,     o.msg_counter_);
        std::swap(expected_appid_,  o.expected_appid_);
        std::swap(key_multicast_,   o.key_multicast_);
    }

    pcap::Handle  handle_         = nullptr;
    Config        cfg_{};
    Mac           local_mac_{};
    bool          open_           = false;
    std::mt19937  rng_;
    uint32_t      msg_counter_    = 0;
    Reassembler   reassembler_;
    std::string   last_error_;
    uint32_t      purge_counter_  = 0;
    uint16_t      expected_appid_ = 0;
    Mac           key_multicast_{};
};

} // namespace l2
