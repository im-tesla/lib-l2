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
              << "  " << exe << " send  <adapter_index> [peer_mac]   Interactive sender (auto-discovers if omitted)\n"
              << "  " << exe << " recv  <adapter_index> [node_name]  Receiver / listener (auto-replies to discovery)\n\n"
              << "  peer_mac  : aa:bb:cc:dd:ee:ff (optional; auto-discovery used if omitted)\n"
              << "  node_name : friendly name announced in discovery (optional)\n\n";
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
    cfg.padding  = true;
    std::memcpy(cfg.key, PSK, l2::KEY_SIZE);

    if (peer && *peer) {
        cfg.peer_mac = l2::parse_mac(peer);
    } else {
        cfg.peer_mac = l2::BROADCAST_MAC;
    }

    if (!ch.open(cfg)) {
        std::cerr << "[ERROR] " << ch.last_error() << "\n";
        return wait_exit(1);
    }

    std::cout << "[OK] Channel open on " << adapters[idx].description << "\n"
              << "     Local MAC : " << l2::mac_to_string(ch.local_mac()) << "\n"
              << "     Node Name : " << ch.node_name() << "\n";

    if (!peer || !*peer) {
        std::cout << "\n[*] No destination MAC specified. Discovering peers on network...\n";
        auto peers = ch.discover_peers(2000);
        if (peers.empty()) {
            std::cout << "[!] No peers responded to discovery beacon.\n"
                      << "    Fallback to broadcast (FF:FF:FF:FF:FF:FF)? [Y/n]: ";
            std::string ans;
            std::getline(std::cin, ans);
            if (!ans.empty() && ans != "y" && ans != "Y") {
                return wait_exit(1);
            }
            ch.set_peer_mac(l2::BROADCAST_MAC);
            std::cout << "    Using broadcast mode.\n\n";
        } else if (peers.size() == 1) {
            ch.set_peer_mac(peers[0].mac);
            std::cout << "[+] Found 1 peer: " << l2::mac_to_string(peers[0].mac);
            if (!peers[0].name.empty()) std::cout << " (\"" << peers[0].name << "\")";
            std::cout << "\n    Connected! Switched to direct stealth unicast.\n\n";
        } else {
            std::cout << "[+] Found " << peers.size() << " peers:\n";
            for (size_t i = 0; i < peers.size(); ++i) {
                std::cout << "    [" << i << "] " << l2::mac_to_string(peers[i].mac);
                if (!peers[i].name.empty()) std::cout << " (\"" << peers[i].name << "\")";
                std::cout << "\n";
            }
            std::cout << "Select peer index [0-" << peers.size() - 1 << "]: ";
            std::string choice;
            std::getline(std::cin, choice);
            int selected = 0;
            if (!choice.empty()) selected = std::atoi(choice.c_str());
            if (selected < 0 || selected >= int(peers.size())) selected = 0;
            ch.set_peer_mac(peers[selected].mac);
            std::cout << "    Selected " << l2::mac_to_string(peers[selected].mac)
                      << ". Switched to direct stealth unicast.\n\n";
        }
    }

    std::cout << "     Peer MAC  : " << l2::mac_to_string(ch.peer_mac()) << "\n"
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

static int mode_recv(const std::vector<l2::AdapterInfo>& adapters, int idx, const char* node_name) {
    l2::L2Channel ch;
    l2::L2Channel::Config cfg;
    cfg.adapter  = adapters[idx].name;
    cfg.peer_mac = l2::BROADCAST_MAC;  // accept from any peer
    cfg.padding  = true;
    cfg.auto_discovery_reply = true;
    if (node_name && *node_name) {
        cfg.node_name = node_name;
    }
    std::memcpy(cfg.key, PSK, l2::KEY_SIZE);

    if (!ch.open(cfg)) {
        std::cerr << "[ERROR] " << ch.last_error() << "\n";
        return wait_exit(1);
    }

    std::cout << "[OK] Listening on " << adapters[idx].description << "\n"
              << "     Local MAC : " << l2::mac_to_string(ch.local_mac()) << "\n"
              << "     Node Name : " << ch.node_name() << "\n"
              << "     Discovery : Auto-reply enabled\n\n"
              << "Waiting for stealth frames... (Ctrl+C to stop)\n\n";

    ch.recv_loop([](const l2::ReceivedMessage& msg) {
        if (msg.type == l2::MsgType::Control) {
            if (!msg.data.empty() && msg.data[0] == uint8_t(l2::ControlCmd::DiscoveryRequest)) {
                std::string req_name = msg.data.size() > 1
                    ? std::string(msg.data.begin() + 1, msg.data.end())
                    : "unknown";
                std::cout << "[DISCOVERY from " << l2::mac_to_string(msg.sender_mac)
                          << " (\"" << req_name << "\")] Auto-replied with node announcement\n";
            }
            return true;
        }

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
        const char* peer = (argc >= 4) ? argv[3] : nullptr;
        return mode_send(adapters, adapter_idx, peer);
    }
    if (mode == "recv") {
        const char* name = (argc >= 4) ? argv[3] : nullptr;
        return mode_recv(adapters, adapter_idx, name);
    }

    print_usage(argv[0]);
    return wait_exit(1);
}