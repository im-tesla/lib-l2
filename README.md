# lib-l2

<p align="center">
  <a href="#readme"><img src="https://img.shields.io/badge/C%2B%2B-20-00599C.svg?style=for-the-badge&logo=c%2B%2B" alt="C++20" /></a>
  <a href="#readme"><img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg?style=for-the-badge" alt="Platforms" /></a>
  <a href="#readme"><img src="https://img.shields.io/badge/Design-Header--Only-success.svg?style=for-the-badge" alt="Header-Only" /></a>
  <a href="#readme"><img src="https://img.shields.io/badge/Cipher-ChaCha20-orange.svg?style=for-the-badge" alt="ChaCha20" /></a>
  <a href="#readme"><img src="https://img.shields.io/badge/Protocol-IEC%2061850%20GOOSE-blueviolet.svg?style=for-the-badge" alt="Protocol" /></a>
</p>

A cross-platform, lightweight, header-only C++20 library for covert, encrypted raw **Layer 2 (Data Link)** communication across **Windows**, **macOS**, and **Linux**.

`lib-l2` transmits data directly inside raw Ethernet frames, completely bypassing Layer 3 (IP) and Layer 4 (TCP/UDP) network stacks. Because it uses no IP addresses, port numbers, or standard transport handshakes, it operates beneath standard OS socket layers, packet inspection filters, and firewall port rules.

---

## Table of Contents

- [Features](#features)
- [Cross-Platform Architecture](#cross-platform-architecture)
- [Frame Architecture](#frame-architecture)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [1. Include Header](#1-include-the-header)
  - [2. Auto-Discovery Sender](#2-sending-with-automatic-peer-discovery)
  - [3. Listening Receiver](#3-receiving--listening)
- [Building the Example CLI](#building-the-example-cli)
  - [Windows](#building-on-windows)
  - [macOS / Linux](#building-on-macos--linux)
- [Running the Interactive Demo](#running-the-demo)
- [API Reference](#api-reference)
- [Security & Disclaimer](#security--disclaimer)

---

## Features

- **Cross-Platform & Header-Only**: Drop [`libl2.h`](src/libl2.h) into any C++20 project. Dynamically loads the platform capture library at runtime—**Npcap** (`wpcap.dll`) on Windows, and built-in system **libpcap** (`libpcap.dylib`) on macOS. Zero build SDKs or static link dependencies required.
- **Pure Layer 2 Networking**: Operates directly on raw Ethernet frames using industrial EtherType `0x88B7` (IEC 61850 GOOSE). Bypasses IP routing, ARP tables, OS firewalls, and port scanners.
- **Automatic Peer Discovery**: No need to manually look up or type 6-byte hexadecimal MAC addresses. Senders emit encrypted discovery beacons (`ControlCmd::DiscoveryRequest`) and receivers auto-announce their friendly node names, seamlessly switching to direct stealth unicast for ongoing communication.
- **Strong Encryption**: End-to-end payload and metadata encryption using **ChaCha20** (256-bit pre-shared key, 96-bit cryptographically random per-frame nonce).
- **Integrity Verification**: 32-bit FNV-1a header checksum validated post-decryption; rejects corrupted frames and wrong keys immediately.
- **Traffic Analysis Resistance**:
  - **Random Length Masking**: Configurable per-frame random padding (default up to 8 bytes) to obscure exact packet sizes and thwart length-based traffic fingerprinting.
  - **Ephemeral MAC Spoofing**: Supports generating random locally-administered unicast MAC addresses per session to prevent hardware MAC fingerprinting.
- **Transparent Fragmentation & Reassembly**: Automatically fragments payloads exceeding standard MTU (1500 bytes) and reassembles them in memory with automatic time-based purging of stale frames.
- **In-Kernel BPF Filtering**: Utilizes BPF driver filtering (`ether[12:2] = 0x88b7`) to drop irrelevant traffic in kernel space before reaching user space, minimizing CPU overhead and latency.

---

## Cross-Platform Architecture

`lib-l2` automatically adapts to your operating system at compile-time and runtime:

| Feature | Windows | macOS | Linux |
|---|---|---|---|
| **Driver / Backend** | Npcap / WinPcap driver | Native BSD BPF (`/dev/bpf*`) | Raw Packet Sockets (`AF_PACKET`) |
| **Runtime Library** | `wpcap.dll` (dynamic `LoadLibrary`) | `libpcap.dylib` (dynamic `dlopen`) | `libpcap.so` (dynamic `dlopen`) |
| **MAC Address Lookup** | Windows IP Helper API (`GetAdaptersAddresses`) | BSD `getifaddrs` + `sockaddr_dl` (`AF_LINK`) | `SIOCGIFHWADDR` ioctl |
| **Node Name Resolution** | `GetComputerNameA` | `gethostname` | `gethostname` |
| **Build Tools** | Visual Studio 2022 / MSBuild | Apple Clang / Make / CMake | GCC / Clang / Make / CMake |
| **Required Permissions** | Administrator | `sudo` / root | `sudo` / `CAP_NET_RAW` |

---

## Frame Architecture

Each transmitted frame is encapsulated in a standard Ethernet II frame camouflaged under the IEC 61850 GOOSE EtherType `0x88B7`:

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
- **OS**: Windows 10 / 11 (x64)
- **Compiler**: Visual Studio 2022 with C++20 support (`/std:c++20`)
- **Runtime**: [Npcap](https://npcap.com/) (installed in WinPcap-compatible mode)
- **Privileges**: Administrator privileges (required for raw adapter access)

### macOS
- **OS**: macOS 12+ (Apple Silicon or Intel)
- **Compiler**: Apple Clang with C++20 (`xcode-select --install`)
- **Runtime**: Built-in system `libpcap` (pre-installed on all macOS versions)
- **Privileges**: `sudo` / root privileges (required for `/dev/bpf*` packet capture/injection)

---

## Quick Start

### 1. Include the Header

Copy [`src/libl2.h`](src/libl2.h) into your project:

```cpp
#include "libl2.h"
```

### 2. Sending with Automatic Peer Discovery

No destination MAC needed—the sender broadcasts an encrypted discovery ping, auto-detects the receiver, and immediately switches to direct stealth unicast:

```cpp
#include "libl2.h"
#include <iostream>

int main() {
    auto adapters = l2::list_adapters();
    if (adapters.empty()) return 1;

    l2::L2Channel channel;
    l2::L2Channel::Config config;
    config.adapter  = adapters[0].name;
    config.padding  = true;

    // 256-bit pre-shared key
    static const uint8_t PSK[l2::KEY_SIZE] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x13, 0x37, 0x42, 0x00, 0xBE, 0xEF, 0xF0, 0x0D
    };
    std::memcpy(config.key, PSK, l2::KEY_SIZE);

    if (!channel.open(config)) {
        std::cerr << "Open failed: " << channel.last_error() << "\n";
        return 1;
    }

    // Auto-discover peer on the local network
    std::cout << "Searching for peers...\n";
    auto peer_mac = channel.discover_peer(2000);
    if (peer_mac) {
        channel.set_peer_mac(*peer_mac);
        std::cout << "Connected to peer: " << l2::mac_to_string(*peer_mac) << "\n";
        
        // Transmit text, raw binary, or JPEG buffers via direct unicast
        channel.send("Hello from Layer 2!");
    }

    channel.close();
    return 0;
}
```

### 3. Receiving / Listening

The receiver listens in promiscuous mode and automatically responds to discovery beacons from authorized peers:

```cpp
#include "libl2.h"
#include <iostream>

int main() {
    auto adapters = l2::list_adapters();
    if (adapters.empty()) return 1;

    l2::L2Channel channel;
    l2::L2Channel::Config config;
    config.adapter              = adapters[0].name;
    config.peer_mac             = l2::BROADCAST_MAC; // Accept from any peer with matching PSK
    config.auto_discovery_reply = true;              // Auto-announce to authorized senders
    config.node_name            = "Alice";           // Friendly node identifier
    std::memcpy(config.key, PSK, l2::KEY_SIZE);

    if (!channel.open(config)) return 1;

    std::cout << "Listening as '" << channel.node_name() << "' on " 
              << l2::mac_to_string(channel.local_mac()) << "...\n";

    channel.recv_loop([](const l2::ReceivedMessage& msg) {
        if (msg.type == l2::MsgType::Text) {
            std::string text(msg.data.begin(), msg.data.end());
            std::cout << "[TEXT from " << l2::mac_to_string(msg.sender_mac) << "]: " 
                      << text << "\n";
        }
        return true; // Return false to exit loop
    });

    channel.close();
    return 0;
}
```

---

## Building the Example CLI

The repository includes a ready-to-use interactive CLI demo in [`src/example.cpp`](src/example.cpp).

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
cmake -B build && cmake --build build
```

#### Direct Clang Compilation
```bash
clang++ -std=c++20 -O2 -Isrc src/example.cpp -o lib-l2
```

---

## Running the Demo

### On Windows (Run Command Prompt / PowerShell as Administrator)
```cmd
# 1. List available network interfaces:
output\lib-l2.exe

# 2. Start receiver (auto-replies to discovery beacons):
output\lib-l2.exe recv <adapter_index> [node_name]

# 3. Start sender (auto-discovers peer and switches to stealth unicast):
output\lib-l2.exe send <adapter_index>
```

### On macOS (Run Terminal with sudo)
```bash
# 1. List available network interfaces (e.g. en0):
sudo ./lib-l2

# 2. Start receiver:
sudo ./lib-l2 recv <adapter_index> [node_name]

# 3. Start sender (auto-discovers peer over LAN):
sudo ./lib-l2 send <adapter_index>
```

### Discovery Terminal Walkthrough
```text
C:\lib-l2> output\lib-l2.exe send 0
[OK] Channel open on Realtek PCIe GbE Family Controller
     Local MAC : 00:19:db:f3:ee:1b
     Node Name : DESKTOP-MAIN

[*] No destination MAC specified. Discovering peers on network...
[+] Found 1 peer: a4:83:e7:21:40:9a ("MacBook-Pro")
    Connected! Switched to direct stealth unicast.

     Peer MAC  : a4:83:e7:21:40:9a
     Padding   : ON

Type messages to send (empty line to quit):
Hello from Windows!
  -> sent 19 bytes in 235 us
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
    std::string name;        // System adapter identifier (pass to Config::adapter)
    std::string description; // Human-friendly device name
    Mac         mac;         // Interface hardware MAC address
};
```

#### `l2::L2Channel::Config`
```cpp
struct Config {
    std::string adapter;                 // System device name (from list_adapters)
    Mac         peer_mac{};              // Destination MAC address
    uint8_t     key[KEY_SIZE]{};         // Pre-shared 256-bit encryption key
    Mac         local_mac{};             // Custom local MAC override (empty = auto-detect)
    bool        random_mac = false;      // Generate random session MAC per run
    bool        padding    = true;       // Add random padding to mask payload length
    size_t      max_pad    = 8;          // Max padding bytes to append
    int         read_timeout_ms = 1;     // pcap read timeout in ms (default: 1)
    bool        auto_discovery_reply = true; // Auto-reply to discovery beacons
    std::string node_name;               // Friendly name (defaults to system hostname)
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
