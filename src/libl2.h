#pragma once

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

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
#elif defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
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
#include <atomic>

namespace l2 {

inline constexpr uint16_t ETHER_TYPE         = 0x88B7;   // IEC 61850 GOOSE
inline constexpr uint16_t FRAME_MAGIC        = 0x4C32;   // "L2"
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
inline constexpr Mac BROADCAST_MAC = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

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
        for (size_t i = 0; i < chunk; ++i)
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

using fn_open_live      = Handle(*)(const char*, int, int, int, char*);
using fn_findalldevs    = int(*)(pcap_if_t**, char*);
using fn_freealldevs    = void(*)(pcap_if_t*);
using fn_sendpacket     = int(*)(Handle, const uint8_t*, int);
using fn_next_ex        = int(*)(Handle, PktHdr**, const uint8_t**);
using fn_close          = void(*)(Handle);
using fn_compile        = int(*)(Handle, BpfProgram*, const char*, int, uint32_t);
using fn_setfilter      = int(*)(Handle, BpfProgram*);
using fn_freecode       = void(*)(BpfProgram*);
using fn_geterr         = char*(*)(Handle);
using fn_datalink       = int(*)(Handle);
using fn_setmintocopy   = int(*)(Handle, int);

struct Library {
#ifdef _WIN32
    HMODULE           dll           = nullptr;
#else
    void*             dll           = nullptr;
#endif
    fn_open_live      open_live     = nullptr;
    fn_findalldevs    findalldevs   = nullptr;
    fn_freealldevs    freealldevs   = nullptr;
    fn_sendpacket     sendpacket    = nullptr;
    fn_next_ex        next_ex       = nullptr;
    fn_close          close         = nullptr;
    fn_compile        compile       = nullptr;
    fn_setfilter      setfilter     = nullptr;
    fn_freecode       freecode      = nullptr;
    fn_geterr         geterr        = nullptr;
    fn_datalink       datalink      = nullptr;
    fn_setmintocopy   setmintocopy  = nullptr;
    bool              loaded        = false;

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

        open_live    = (fn_open_live)   get("pcap_open_live");
        findalldevs  = (fn_findalldevs) get("pcap_findalldevs");
        freealldevs  = (fn_freealldevs) get("pcap_freealldevs");
        sendpacket   = (fn_sendpacket)  get("pcap_sendpacket");
        next_ex      = (fn_next_ex)     get("pcap_next_ex");
        close        = (fn_close)       get("pcap_close");
        compile      = (fn_compile)     get("pcap_compile");
        setfilter    = (fn_setfilter)   get("pcap_setfilter");
        freecode     = (fn_freecode)    get("pcap_freecode");
        geterr       = (fn_geterr)      get("pcap_geterr");
        datalink     = (fn_datalink)    get("pcap_datalink");
        setmintocopy = (fn_setmintocopy)get("pcap_setmintocopy");

        loaded = open_live && findalldevs && freealldevs && sendpacket &&
                 next_ex && close && compile && setfilter && freecode &&
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
        if (info.mac != Mac{})
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

    detail::write_be16(p, FRAME_MAGIC); p += 2;

    uint8_t nonce[NONCE_SIZE];
    std::uniform_int_distribution<uint32_t> byte_dist(0, 255);
    for (auto& b : nonce) b = uint8_t(byte_dist(rng));
    std::memcpy(p, nonce, NONCE_SIZE); p += NONCE_SIZE;

    size_t avail_for_pad = MAX_FRAG_PAYLOAD - hdr.payload_len;
    size_t pad_len = 0;
    if (max_pad > 0 && avail_for_pad > 0)
        pad_len = std::uniform_int_distribution<size_t>(0, std::min(max_pad, avail_for_pad))(rng);

    size_t plain_len = INNER_HDR_SIZE + hdr.payload_len + pad_len;
    uint8_t plain[MAX_ETH_FRAME];   // stack buffer (max ~1472 bytes used)

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

    for (size_t i = 0; i < pad_len; ++i) *h++ = uint8_t(byte_dist(rng));

    detail::chacha20_crypt(key, nonce, plain, p, plain_len);
    p += plain_len;

    return size_t(p - out);
}

inline bool parse(const uint8_t* frame, size_t frame_len,
                  const uint8_t key[KEY_SIZE],
                  Mac& sender_mac, InnerHeader& hdr,
                  std::vector<uint8_t>& payload_out) {

    if (frame_len < TOTAL_OVERHEAD) return false;

    const uint8_t* p = frame;

    p += 6;  // skip dst
    std::memcpy(sender_mac.data(), p, 6); p += 6;

    if (detail::read_be16(p) != ETHER_TYPE) return false;
    p += 2;

    if (detail::read_be16(p) != FRAME_MAGIC) return false;
    p += 2;

    uint8_t nonce[NONCE_SIZE];
    std::memcpy(nonce, p, NONCE_SIZE); p += NONCE_SIZE;

    size_t enc_len = frame_len - CLEAR_OVERHEAD;
    if (enc_len < INNER_HDR_SIZE) return false;

    uint8_t plain[MAX_ETH_FRAME];
    detail::chacha20_crypt(key, nonce, p, plain, enc_len);

    const uint8_t* h = plain;
    hdr.msg_id      = detail::read_be32(h); h += 4;
    hdr.frag_idx    = detail::read_be16(h); h += 2;
    hdr.frag_total  = detail::read_be16(h); h += 2;
    hdr.msg_type    = MsgType(*h++);
    hdr.flags       = MsgFlags(*h++);
    hdr.payload_len = detail::read_be16(h); h += 2;

    uint32_t expected_check = detail::fnv1a(plain, 12);
    uint32_t actual_check   = detail::read_be32(h); h += 4;
    if (expected_check != actual_check) return false;  // wrong key or corruption

    if (hdr.frag_total == 0) return false;
    if (hdr.frag_idx >= hdr.frag_total) return false;
    if (hdr.payload_len > enc_len - INNER_HDR_SIZE) return false;

    payload_out.assign(h, h + hdr.payload_len);
    return true;
}

} // namespace frame

class Reassembler {
public:
    std::optional<ReceivedMessage> add(const Mac& sender,
                                       const frame::InnerHeader& hdr,
                                       const std::vector<uint8_t>& payload) {
        auto& buf = buffers_[hdr.msg_id];

        if (buf.fragments.empty()) {
            buf.frag_total  = hdr.frag_total;
            buf.msg_type    = hdr.msg_type;
            buf.sender_mac  = sender;
            buf.fragments.resize(hdr.frag_total);
            buf.received.resize(hdr.frag_total, false);
            buf.created     = std::chrono::steady_clock::now();
        }

        if (hdr.frag_idx >= buf.frag_total) return std::nullopt;

        if (!buf.received[hdr.frag_idx]) {
            buf.received[hdr.frag_idx] = true;
            buf.fragments[hdr.frag_idx] = payload;
            ++buf.count;
        }

        if (buf.count == buf.frag_total) {
            ReceivedMessage msg;
            msg.type       = buf.msg_type;
            msg.sender_mac = buf.sender_mac;

            size_t total = 0;
            for (auto& f : buf.fragments) total += f.size();
            msg.data.reserve(total);
            for (auto& f : buf.fragments)
                msg.data.insert(msg.data.end(), f.begin(), f.end());

            buffers_.erase(hdr.msg_id);
            return msg;
        }

        return std::nullopt;
    }

    void purge(std::chrono::seconds max_age = std::chrono::seconds(10)) {
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

    std::unordered_map<uint32_t, Buffer> buffers_;
};

class L2Channel {
public:
    struct Config {
        std::string adapter;          // pcap device name (from list_adapters)
        Mac         peer_mac{};       // destination MAC address
        uint8_t     key[KEY_SIZE]{};  // pre-shared 256-bit encryption key
        Mac         local_mac{};      // custom local MAC (empty = auto-detect)
        bool        random_mac  = false;  // generate random session MAC
        bool        padding     = true;   // enable random per-frame padding
        size_t      max_pad     = DEFAULT_MAX_PAD;  // max padding bytes
        int         read_timeout_ms = 1;  // pcap read timeout (lower = less latency)
        bool        auto_discovery_reply = true; // automatically reply to discovery requests
        std::string node_name;        // friendly name announced in discovery
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
        handle_ = pcap::lib().open_live(
            cfg_.adapter.c_str(),
            MAX_ETH_FRAME + 64,       // snaplen
            1,                         // promiscuous
            cfg_.read_timeout_ms,      // read timeout (ms)
            errbuf
        );
        if (!handle_) {
            last_error_ = std::string("pcap_open_live: ") + errbuf;
            return false;
        }

        if (pcap::lib().datalink(handle_) != 1 /* DLT_EN10MB */) {
            last_error_ = "Adapter is not Ethernet (DLT_EN10MB required)";
            pcap::lib().close(handle_);
            handle_ = nullptr;
            return false;
        }

        if (pcap::lib().setmintocopy)
            pcap::lib().setmintocopy(handle_, 1);

        pcap::BpfProgram bpf{};
        const char* filter = "ether[12:2] = 0x88b7";
        if (pcap::lib().compile(handle_, &bpf, filter, 1, 0) == 0) {
            pcap::lib().setfilter(handle_, &bpf);
            pcap::lib().freecode(&bpf);
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

    bool send_to(const Mac& dst, const void* data, size_t len, MsgType type) {
        if (!open_) { last_error_ = "Channel not open"; return false; }

        const uint8_t* bytes = static_cast<const uint8_t*>(data);
        uint32_t msg_id = msg_counter_++;

        size_t max_payload = cfg_.padding
            ? (MAX_FRAG_PAYLOAD - cfg_.max_pad)
            : MAX_FRAG_PAYLOAD;

        uint16_t frag_total = uint16_t(len > 0 ? (len + max_payload - 1) / max_payload : 1);

        uint8_t frame_buf[MAX_ETH_FRAME + 64];

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

    std::vector<DiscoveredPeer> discover_peers(int timeout_ms = 1500, const std::string& request_name = "") {
        std::vector<DiscoveredPeer> peers;
        if (!open_) { last_error_ = "Channel not open"; return peers; }

        std::string req_name = request_name.empty() ? cfg_.node_name : request_name;
        std::vector<uint8_t> req;
        req.push_back(uint8_t(ControlCmd::DiscoveryRequest));
        req.insert(req.end(), req_name.begin(), req_name.end());

        if (!send_to(BROADCAST_MAC, req.data(), req.size(), MsgType::Control))
            return peers;

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) break;

            int step_timeout = int(std::min<int64_t>(remaining, 50));
            auto msg = recv(step_timeout);
            if (msg.has_value() && msg->type == MsgType::Control && !msg->data.empty()) {
                if (msg->data[0] == uint8_t(ControlCmd::DiscoveryResponse)) {
                    auto it = std::find_if(peers.begin(), peers.end(),
                        [&](const DiscoveredPeer& p) { return p.mac == msg->sender_mac; });
                    if (it == peers.end()) {
                        DiscoveredPeer p;
                        p.mac = msg->sender_mac;
                        if (msg->data.size() > 1) {
                            p.name.assign(msg->data.begin() + 1, msg->data.end());
                        }
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

    std::optional<ReceivedMessage> recv(int timeout_ms = 1000) {
        if (!open_) return std::nullopt;

        auto deadline = std::chrono::steady_clock::now()
                      + std::chrono::milliseconds(timeout_ms);

        while (std::chrono::steady_clock::now() < deadline) {
            pcap::PktHdr* pkt_hdr    = nullptr;
            const uint8_t* pkt_data  = nullptr;

            int res = pcap::lib().next_ex(handle_, &pkt_hdr, &pkt_data);
            if (res != 1 || !pkt_data) continue;

            if (pkt_hdr->caplen < TOTAL_OVERHEAD) continue;

            Mac sender{};
            frame::InnerHeader hdr{};
            std::vector<uint8_t> payload;

            if (!frame::parse(pkt_data, pkt_hdr->caplen, cfg_.key,
                              sender, hdr, payload))
                continue;

            if (sender == local_mac_) continue;

            Mac dst;
            std::memcpy(dst.data(), pkt_data, 6);

            if (dst != local_mac_ && dst != BROADCAST_MAC) continue;

            auto msg = reassembler_.add(sender, hdr, payload);
            if (msg.has_value()) {
                if (msg->type == MsgType::Control && !msg->data.empty() &&
                    msg->data[0] == uint8_t(ControlCmd::DiscoveryRequest) &&
                    cfg_.auto_discovery_reply) {
                    std::vector<uint8_t> resp;
                    resp.push_back(uint8_t(ControlCmd::DiscoveryResponse));
                    resp.insert(resp.end(), cfg_.node_name.begin(), cfg_.node_name.end());
                    send_to(msg->sender_mac, resp.data(), resp.size(), MsgType::Control);
                }
                return msg;
            }

            if (++purge_counter_ % 1000 == 0)
                reassembler_.purge();
        }

        return std::nullopt;
    }

    std::optional<ReceivedMessage> try_recv() {
        return recv(0);
    }

    void recv_loop(std::function<bool(const ReceivedMessage&)> callback,
                   int timeout_ms = -1) {
        auto start = std::chrono::steady_clock::now();
        while (open_) {
            auto msg = recv(100);
            if (msg.has_value()) {
                if (!callback(*msg)) return;
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
        std::swap(handle_,        o.handle_);
        std::swap(cfg_,           o.cfg_);
        std::swap(local_mac_,     o.local_mac_);
        std::swap(open_,          o.open_);
        std::swap(rng_,           o.rng_);
        std::swap(last_error_,    o.last_error_);
        std::swap(reassembler_,   o.reassembler_);
        std::swap(purge_counter_, o.purge_counter_);
        uint32_t tmp = msg_counter_.load();
        msg_counter_.store(o.msg_counter_.load());
        o.msg_counter_.store(tmp);
    }

    pcap::Handle              handle_        = nullptr;
    Config                    cfg_{};
    Mac                       local_mac_{};
    bool                      open_          = false;
    std::mt19937              rng_;
    std::atomic<uint32_t>     msg_counter_{0};
    Reassembler               reassembler_;
    std::string               last_error_;
    uint32_t                  purge_counter_ = 0;
};

} // namespace l2
