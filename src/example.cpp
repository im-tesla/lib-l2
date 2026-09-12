// ============================================================================
// lib-l2 Example: Stealth L2 Communication Demo
//
// Usage:
//   lib-l2.exe send <adapter_index> <peer_mac>    Send interactive text messages
//   lib-l2.exe recv <adapter_index>               Receive and display messages
//
// Both sides must use the same pre-shared key.
// Run as Administrator (Npcap requires elevation for raw capture).
// ============================================================================

#include "libl2.h"
#include <iostream>
#include <string>
#include <cstdlib>

static int wait_exit(int code) {
    std::cout << "\nPress Enter twice to exit...";
    std::cin.ignore(0x7FFFFFFF, '\n');
    std::cin.get();
    return code;
}

static const uint8_t PSK[l2::KEY_SIZE] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x13, 0x37, 0x42, 0x00, 0xBE, 0xEF, 0xF0, 0x0D,
};

static void print_usage(const char* exe) {
    std::cout << "lib-l2 example\n"
              << "========================\n\n"
              << "Usage:\n"
              << "  " << exe << " send  <adapter_index> <peer_mac>   Interactive sender\n"
              << "  " << exe << " recv  <adapter_index>              Receiver / listener\n\n"
              << "  peer_mac format: aa:bb:cc:dd:ee:ff\n\n";
}

static void list_all_adapters(const std::vector<l2::AdapterInfo>& adapters) {
    std::cout << "Network adapters:\n";
    for (size_t i = 0; i < adapters.size(); ++i) {
        std::cout << "  [" << i << "] " << adapters[i].description
                  << "  MAC: " << l2::mac_to_string(adapters[i].mac) << "\n";
    }
    std::cout << "\n";
}

static int mode_send(const std::vector<l2::AdapterInfo>& adapters, int idx, const char* peer) {
    l2::L2Channel ch;
    l2::L2Channel::Config cfg;
    cfg.adapter  = adapters[idx].name;
    cfg.peer_mac = l2::parse_mac(peer);
    cfg.padding  = true;
    std::memcpy(cfg.key, PSK, l2::KEY_SIZE);

    if (!ch.open(cfg)) {
        std::cerr << "[ERROR] " << ch.last_error() << "\n";
        return wait_exit(1);
    }

    std::cout << "[OK] Channel open on " << adapters[idx].description << "\n"
              << "     Local MAC : " << l2::mac_to_string(ch.local_mac()) << "\n"
              << "     Peer  MAC : " << l2::mac_to_string(cfg.peer_mac) << "\n"
              << "     Padding   : " << (cfg.padding ? "ON" : "OFF") << "\n\n"
              << "Type messages to send (empty line to quit):\n\n";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) break;

        auto t0 = std::chrono::high_resolution_clock::now();
        bool ok = ch.send(line);
        auto t1 = std::chrono::high_resolution_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

        if (ok)
            std::cout << "  -> sent " << line.size() << " bytes in " << us << " us\n";
        else
            std::cerr << "  [FAIL] " << ch.last_error() << "\n";
    }

    return 0;
}

static int mode_recv(const std::vector<l2::AdapterInfo>& adapters, int idx) {
    l2::L2Channel ch;
    l2::L2Channel::Config cfg;
    cfg.adapter  = adapters[idx].name;
    cfg.peer_mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // accept from any peer
    cfg.padding  = true;
    std::memcpy(cfg.key, PSK, l2::KEY_SIZE);

    if (!ch.open(cfg)) {
        std::cerr << "[ERROR] " << ch.last_error() << "\n";
        return wait_exit(1);
    }

    std::cout << "[OK] Listening on " << adapters[idx].description << "\n"
              << "     Local MAC : " << l2::mac_to_string(ch.local_mac()) << "\n\n"
              << "Waiting for stealth frames... (Ctrl+C to stop)\n\n";

    ch.recv_loop([](const l2::ReceivedMessage& msg) {
        const char* type_str = "???";
        switch (msg.type) {
            case l2::MsgType::Text:    type_str = "TEXT"; break;
            case l2::MsgType::Jpeg:    type_str = "JPEG"; break;
            case l2::MsgType::Binary:  type_str = "BIN";  break;
            case l2::MsgType::Control: type_str = "CTRL"; break;
        }

        std::cout << "[" << type_str << " from "
                  << l2::mac_to_string(msg.sender_mac) << "] "
                  << msg.data.size() << " bytes";

        if (msg.type == l2::MsgType::Text)
            std::cout << ": " << std::string(msg.data.begin(), msg.data.end());

        std::cout << "\n";
        return true;  // keep listening
    });

    return 0;
}

int main(int argc, char* argv[]) {
    auto adapters = l2::list_adapters();
    if (adapters.empty()) {
        std::cerr << "No network adapters found.\n"
                  << "Make sure Npcap is installed and you are running as Administrator.\n";
        return wait_exit(1);
    }

    list_all_adapters(adapters);

    if (argc < 3) {
        print_usage(argv[0]);
        return wait_exit(1);
    }

    std::string mode = argv[1];
    int adapter_idx  = std::atoi(argv[2]);

    if (adapter_idx < 0 || adapter_idx >= int(adapters.size())) {
        std::cerr << "Invalid adapter index (valid: 0-" << adapters.size() - 1 << ")\n";
        return wait_exit(1);
    }

    if (mode == "send") {
        if (argc < 4) { std::cerr << "send mode requires <peer_mac>\n"; return wait_exit(1); }
        return mode_send(adapters, adapter_idx, argv[3]);
    }
    if (mode == "recv") {
        return mode_recv(adapters, adapter_idx);
    }

    print_usage(argv[0]);
    return wait_exit(1);
}