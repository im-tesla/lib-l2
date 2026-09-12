# lib-l2

A lightweight, header-only C++20 library for covert, encrypted raw **Layer 2 (Data Link)** communication on Windows and macOS (with Linux support).

`lib-l2` transmits data directly over raw Ethernet frames, completely bypassing the Layer 3 (IP) and Layer 4 (TCP/UDP) network stacks. Because it does not use IP addresses, port numbers, or standard transport handshakes, it operates beneath standard OS socket layers and packet filtering rules.

---

## Features

- **Cross-Platform & Header-Only**: Just include [`libl2.h`](src/libl2.h). Dynamically loads the platform packet capture library at runtime—**Npcap** (`wpcap.dll`) on Windows, and built-in **libpcap** (`libpcap.dylib`) on macOS. Zero build SDKs or static link dependencies required.
- **Pure Layer 2 Networking**: Operates directly on raw Ethernet frames (EtherType `0x88B7`, IEC 61850 GOOSE). Bypasses IP routing, ARP tables, OS firewalls, and port scanners.
- **Automatic Peer Discovery**: No need to manually look up or type destination MAC addresses. Nodes broadcast encrypted discovery beacons (`ControlCmd::DiscoveryRequest`) and automatically reply with their friendly node names, seamlessly switching to stealth unicast for ongoing communication.
- **Strong Encryption**: End-to-end payload and metadata encryption using **ChaCha20** (256-bit pre-shared key, 96-bit random per-frame nonce).
- **Integrity Verification**: 32-bit FNV-1a header checksum validated post-decryption; rejects invalid packets and wrong keys immediately.
- **Traffic Analysis Resistance**:
  - **Random Padding**: Configurable per-frame random padding (default up to 8 bytes) to obscure exact packet sizes and prevent size-based fingerprinting.
  - **Ephemeral MAC Spoofing**: Supports generating random locally-administered unicast MAC addresses per session or specifying custom static MACs.
- **Automatic Fragmentation & Reassembly**: Transparently splits messages exceeding the standard Ethernet MTU (1500 bytes) into multiple fragments and reassembles them in memory with automatic stale-packet purging.
- **Low-Latency & Kernel BPF Filtering**: Utilizes BPF kernel filtering (`ether[12:2] = 0x88b7`) to discard non-matching traffic in the driver before reaching user space, with minimal buffer delays.

---

## Frame Architecture

Each transmitted frame is encapsulated in a standard Ethernet II frame using the industrial EtherType `0x88B7` (IEC 61850 GOOSE):

```
+-------------------------------------------------------------------------------+
|                             Cleartext Ethernet II                             |
+-------------------+-------------------+-------------------+-------------------+
|  Destination MAC  |    Source MAC     | EtherType: 0x88B7 |   Magic: 0x4C32   |
|     (6 bytes)     |     (6 bytes)     |     (2 bytes)     |      ("L2")       |
+-------------------+-------------------+-------------------+-------------------+
|  ChaCha20 Nonce   |                                                           |
|    (12 bytes)     |                                                           |
+-------------------+-----------------------------------------------------------+
|                      Encrypted with ChaCha20 (256-bit Key)                     |
+-------------------+-------------------+-------------------+-------------------+
|   Message ID      |   Fragment Index  |   Fragment Total  | Msg Type | Flags  |
|    (4 bytes)      |     (2 bytes)     |     (2 bytes)     |  (1 B)   | (1 B)  |
+-------------------+-------------------+-------------------+-------------------+
|   Payload Length  |   FNV-1a Check    |                  Payload              |
|     (2 bytes)     |     (4 bytes)     |             (0 - 1456 bytes)          |
+-------------------+-------------------+-------------------+-------------------+
|  Random Padding   |
|   (0 - N bytes)   |
+-------------------+
```

### Overhead Breakdown

| Section | Size | Description |
|---|---|---|
| Ethernet Header | 14 bytes | Dst MAC (6B) + Src MAC (6B) + EtherType (2B) |
| Magic Tag | 2 bytes | ASCII `"L2"` (`0x4C32`) |
| Nonce | 12 bytes | Cryptographically random per-frame ChaCha20 nonce |
| **Cleartext Overhead** | **28 bytes** | Visible on the wire |
| Inner Header | 16 bytes | Msg ID (4B) + Frag Idx (2B) + Frag Total (2B) + Type (1B) + Flags (1B) + Payload Len (2B) + FNV-1a Checksum (4B) |
| Payload | 0 – 1456 bytes | User payload data |
| Padding | 0 – 8 bytes | Random bytes for length masking |
| **Max Ethernet Frame** | **1500 bytes** | Standard MTU limit (Payload ≤ 1456 bytes) |

---

## Requirements

### Windows
- Windows 10 / 11 (x64)
- Visual Studio 2022 with C++20 (`/std:c++20`)
- [Npcap](https://npcap.com/) (installed in WinPcap-compatible mode)
- Administrator privileges (for raw packet capture)

### macOS
- macOS 12+ (Apple Silicon or Intel)
- Apple Clang with C++20 (`clang++ -std=c++20`, via `xcode-select --install`)
- Built-in system `libpcap` (pre-installed on all Macs)
- `sudo` / root privileges (required for raw `/dev/bpf*` packet access)

---

## Quick Start

### 1. Include the Header

Copy [`libl2.h`](src/libl2.h) into your project. Include Windows sockets and the header:

```cpp
#include "libl2.h"
```

### 2. Sending Data

```cpp
#include "libl2.h"
#include <iostream>

int main() {
    // 1. Discover adapters
    auto adapters = l2::list_adapters();
    if (adapters.empty()) {
        std::cerr << "No adapters found or Npcap not installed.\n";
        return 1;
    }

    // 2. Configure channel
    l2::L2Channel channel;
    l2::L2Channel::Config config;
    config.adapter  = adapters[0].name;                         // Target Npcap adapter
    config.peer_mac = l2::parse_mac("00:11:22:33:44:55");       // Destination MAC
    config.padding  = true;                                     // Enable traffic masking

    // 256-bit pre-shared key
    static const uint8_t PSK[l2::KEY_SIZE] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    std::memcpy(config.key, PSK, l2::KEY_SIZE);

    if (!channel.open(config)) {
        std::cerr << "Open failed: " << channel.last_error() << "\n";
        return 1;
    }

    // 3. Send text, binary data, or JPEG
    channel.send("Hello from Layer 2!");
    channel.close();
    return 0;
}
```

### 3. Receiving Data

```cpp
#include "libl2.h"
#include <iostream>

int main() {
    auto adapters = l2::list_adapters();
    if (adapters.empty()) return 1;

    l2::L2Channel channel;
    l2::L2Channel::Config config;
    config.adapter  = adapters[0].name;
    config.peer_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // Accept broadcast / any peer
    std::memcpy(config.key, PSK, l2::KEY_SIZE);

    if (!channel.open(config)) {
        std::cerr << "Open failed: " << channel.last_error() << "\n";
        return 1;
    }

    // Blocking receive loop
    channel.recv_loop([](const l2::ReceivedMessage& msg) {
        std::cout << "Received " << msg.data.size() << " bytes from "
                  << l2::mac_to_string(msg.sender_mac) << "\n";

        if (msg.type == l2::MsgType::Text) {
            std::string text(msg.data.begin(), msg.data.end());
            std::cout << "Content: " << text << "\n";
        }
        return true; // Return false to break out of loop
    });

    channel.close();
    return 0;
}
```

---

## Building the Example

The repository includes a ready-to-run interactive CLI demonstration in [`src/example.cpp`](src/example.cpp).

### Building on Windows

#### Using Visual Studio
1. Open [`lib-l2.slnx`](lib-l2.slnx) in Visual Studio 2022.
2. Select **Release** and **x64**.
3. Build the solution (`Ctrl + Shift + B`). Executable will be in `output\lib-l2.exe`.

#### Using MSBuild
```cmd
msbuild src\lib-l2.vcxproj /p:Configuration=Release /p:Platform=x64
```

### Building on macOS / Linux

#### Using Make
```bash
make
```

#### Using CMake
```bash
cmake -B build
cmake --build build
```

#### Direct Clang Compilation
```bash
clang++ -std=c++20 -O2 -Isrc src/example.cpp -o lib-l2
```

---

### Running the Demo

#### On Windows (Run Command Prompt / Terminal as Administrator)
```cmd
# 1. List adapters:
output\lib-l2.exe

# 2. Start receiver:
output\lib-l2.exe recv <adapter_index> [node_name]

# 3. Start sender (auto-discovers receiver and connects via stealth unicast):
output\lib-l2.exe send <adapter_index>
```

#### On macOS (Run Terminal with sudo)
```bash
# 1. List adapters:
sudo ./lib-l2

# 2. Start receiver:
sudo ./lib-l2 recv <adapter_index> [node_name]

# 3. Start sender (auto-discovers receiver and connects via stealth unicast):
sudo ./lib-l2 send <adapter_index>
```

---

## API Reference

### Structs & Types

#### `l2::Mac` & `l2::BROADCAST_MAC`
```cpp
using Mac = std::array<uint8_t, 6>;
inline constexpr Mac BROADCAST_MAC = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
```

#### `l2::ControlCmd`
```cpp
enum class ControlCmd : uint8_t {
    DiscoveryRequest  = 0x01,
    DiscoveryResponse = 0x02,
    Ping              = 0x03,
    Pong              = 0x04,
};
```

#### `l2::DiscoveredPeer`
```cpp
struct DiscoveredPeer {
    Mac         mac{};  // Discovered hardware or session MAC
    std::string name;   // Friendly node name (e.g. computer hostname)
};
```

#### `l2::MsgType`
```cpp
enum class MsgType : uint8_t {
    Text    = 0x01,
    Jpeg    = 0x02,
    Binary  = 0x03,
    Control = 0xFF,
};
```

#### `l2::ReceivedMessage`
```cpp
struct ReceivedMessage {
    MsgType              type;        // Type identifier of message
    std::vector<uint8_t> data;        // Reassembled payload bytes
    Mac                  sender_mac;  // Physical MAC of the sender
};
```

#### `l2::AdapterInfo`
```cpp
struct AdapterInfo {
    std::string name;        // Npcap device path (pass to Config::adapter)
    std::string description; // Human-friendly device name
    Mac         mac;         // Interface hardware MAC address
};
```

#### `l2::L2Channel::Config`
```cpp
struct Config {
    std::string adapter;                 // Npcap device name (from list_adapters)
    Mac         peer_mac{};              // Destination MAC address
    uint8_t     key[KEY_SIZE]{};         // Pre-shared 256-bit encryption key
    Mac         local_mac{};             // Custom local MAC override (empty = auto-detect)
    bool        random_mac = false;      // Generate random session MAC per run
    bool        padding    = true;       // Add random padding to mask payload length
    size_t      max_pad    = 8;          // Max padding bytes to append
    int         read_timeout_ms = 1;     // pcap read timeout in ms (default: 1)
    bool        auto_discovery_reply = true; // Auto-reply to discovery beacons
    std::string node_name;               // Friendly name (defaults to Windows COMPUTERNAME)
};
```

### Functions

| Function | Description |
|---|---|
| `l2::list_adapters()` | Enumerates all network adapters with valid MAC addresses. Returns `std::vector<AdapterInfo>`. |
| `l2::parse_mac(const std::string& str)` | Parses a MAC string in `"aa:bb:cc:dd:ee:ff"` format into `l2::Mac`. |
| `l2::mac_to_string(const l2::Mac& m)` | Formats `l2::Mac` into standard colon-separated hex string representation. |

### `l2::L2Channel`

| Method | Description |
|---|---|
| `bool open(const Config& cfg)` | Opens adapter in raw promiscuous mode, compiles BPF filter, and initializes encryption. |
| `void close()` | Closes the adapter and frees internal pcap resources. |
| `bool is_open() const` | Returns `true` if the channel is currently open. |
| `const Mac& local_mac() const` | Returns the local MAC address currently in use. |
| `const Mac& peer_mac() const` | Returns currently configured destination peer MAC. |
| `void set_peer_mac(const Mac& mac)` | Dynamically updates destination peer MAC. |
| `const std::string& node_name() const` | Returns friendly node name. |
| `void set_node_name(const std::string& name)` | Sets friendly node name announced in discovery responses. |
| `const std::string& last_error() const`| Returns the last recorded error message. |
| `std::vector<DiscoveredPeer> discover_peers(timeout_ms = 1500)` | Broadcasts an encrypted discovery beacon and returns all responding peers. |
| `std::optional<Mac> discover_peer(timeout_ms = 1500)` | Convenience method returning the MAC of the first discovered peer. |
| `bool send(const void* data, size_t len, MsgType type)` | Fragments, encrypts, and transmits data to `peer_mac()`. |
| `bool send_to(const Mac& dst, const void* data, size_t len, MsgType type)` | Transmits data directly to a specific target MAC. |
| `bool send(const std::string& text)` | Helper to transmit a `MsgType::Text` string. |
| `bool send_jpeg(const void* data, size_t len)` | Helper to transmit a `MsgType::Jpeg` image buffer. |
| `bool send_binary(const void* data, size_t len)` | Helper to transmit a `MsgType::Binary` raw buffer. |
| `std::optional<ReceivedMessage> recv(int timeout_ms = 1000)` | Receives and reassembles incoming messages with a timeout. |
| `std::optional<ReceivedMessage> try_recv()` | Non-blocking poll for incoming messages (`recv(0)`). |
| `void recv_loop(callback, timeout_ms = -1)` | Continuously receives frames and calls `callback(const ReceivedMessage&)`. |

---

## Security & Disclaimer

This software is designed for educational purposes, network protocol research, and covert-channel defensive evaluation. Ensure you have authorization before capturing or injecting raw network packets on any network.
