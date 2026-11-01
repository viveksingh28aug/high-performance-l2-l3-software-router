#include "router/packet_forwarder.h"
#include "router/packet_io.h"
#include "router/ethernet.h"
#include "router/ipv4.h"
#include "router/arp.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <thread>
#include <csignal>

static volatile bool g_running = true;

void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

void print_banner() {
    std::cout << "===================================================================\n";
    std::cout << "  High-Performance Layer 2 / Layer 3 Software Router (C11/C++17)   \n";
    std::cout << "  Linux Software Data Plane - Cisco / Silicon One Architecture     \n";
    std::cout << "===================================================================\n\n";
}

void print_help(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --offline               Run deterministic offline simulation (default)\n"
              << "  --live                  Enable live AF_PACKET raw socket I/O\n"
              << "  --interface <ifname>    Network interface for live I/O (e.g. eth0, veth0)\n"
              << "  --benchmark             Run in-app micro-benchmarks\n"
              << "  --help                  Show this help message\n\n"
              << "NOTE: Offline mode is the default and does NOT modify host network traffic.\n"
              << "Live mode requires root privileges (CAP_NET_RAW) and an active interface.\n";
}

void print_statistics(const router::router_stats_t& stats) {
    std::cout << "\n----------------------- ROUTER TELEMETRY & STATS -----------------------\n";
    std::cout << std::left << std::setw(32) << "RX Packets:" << stats.rx_packets << "\n";
    std::cout << std::left << std::setw(32) << "RX Bytes:" << stats.rx_bytes << "\n";
    std::cout << std::left << std::setw(32) << "TX Packets:" << stats.tx_packets << "\n";
    std::cout << std::left << std::setw(32) << "TX Bytes:" << stats.tx_bytes << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(32) << "L2 Broadcast Packets:" << stats.l2_broadcast_packets << "\n";
    std::cout << std::left << std::setw(32) << "L2 802.1Q VLAN Tagged:" << stats.l2_vlan_tagged_packets << "\n";
    std::cout << std::left << std::setw(32) << "L2 Frame Errors (short/long):"
              << (stats.l2_frame_too_short + stats.l2_frame_too_long) << "\n";
    std::cout << std::left << std::setw(32) << "L2 MAC Mismatch (dropped):" << stats.l2_dst_mac_mismatch << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(32) << "L3 IPv4 Packets:" << stats.l3_ipv4_packets << "\n";
    std::cout << std::left << std::setw(32) << "L3 Forwarded Packets:" << stats.l3_forwarded << "\n";
    std::cout << std::left << std::setw(32) << "L3 Local Terminated:" << stats.l3_local_delivered << "\n";
    std::cout << std::left << std::setw(32) << "L3 Checksum Errors (dropped):" << stats.l3_checksum_errors << "\n";
    std::cout << std::left << std::setw(32) << "L3 TTL Expired (dropped):" << stats.l3_ttl_expired << "\n";
    std::cout << std::left << std::setw(32) << "L3 No Route (dropped):" << stats.l3_no_route << "\n";
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(32) << "ARP Requests Received:" << stats.arp_requests_received << "\n";
    std::cout << std::left << std::setw(32) << "ARP Replies Sent:" << stats.arp_replies_sent << "\n";
    std::cout << std::left << std::setw(32) << "ARP Cache Hits:" << stats.arp_cache_hits << "\n";
    std::cout << std::left << std::setw(32) << "ARP Cache Misses:" << stats.arp_cache_misses << "\n";
    std::cout << std::left << std::setw(32) << "ARP Pending Buffered:" << stats.arp_pending_queued << "\n";
    std::cout << std::left << std::setw(32) << "ARP Pending Dequeued:" << stats.arp_pending_dequeued << "\n";
    std::cout << "------------------------------------------------------------------------\n";
}

void run_offline_simulation() {
    std::cout << "[INFO] Initializing Offline Simulation Environment...\n";

    router::PacketForwarder router;

    // Interface 1: GigabitEthernet0/0/0 (LAN 1)
    router::network_interface_t iface1;
    iface1.id = 1;
    iface1.name = "Gi0/0/0";
    iface1.mac_addr = router::mac_address_t(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x01);
    iface1.ip_addr = router::ipv4_address_t(192, 168, 1, 1);
    iface1.netmask = router::ipv4_address_t(255, 255, 255, 0); // /24
    iface1.mtu = 1500;
    iface1.is_up = true;
    router.add_interface(iface1);

    // Interface 2: GigabitEthernet0/0/1 (WAN / Next-hop router)
    router::network_interface_t iface2;
    iface2.id = 2;
    iface2.name = "Gi0/0/1";
    iface2.mac_addr = router::mac_address_t(0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x02);
    iface2.ip_addr = router::ipv4_address_t(10, 0, 0, 1);
    iface2.netmask = router::ipv4_address_t(255, 255, 255, 252); // /30
    iface2.mtu = 1500;
    iface2.is_up = true;
    router.add_interface(iface2);

    // Install Default Route via 10.0.0.2 on Gi0/0/1
    router.routing_table().set_default_route(router::ipv4_address_t(10, 0, 0, 2), iface2.id, 10);

    // Install Specific Longest Prefix Route for 172.16.0.0/16 via 10.0.0.2 on Gi0/0/1
    router.routing_table().add_route(router::ipv4_address_t(172, 16, 0, 0), 16,
                                     router::ipv4_address_t(10, 0, 0, 2), iface2.id, 5);

    // Pre-populate ARP entry for WAN Gateway 10.0.0.2
    router::mac_address_t wan_gw_mac(0x00, 0x50, 0x56, 0xAA, 0xBB, 0xCC);
    router.arp_cache().update(router::ipv4_address_t(10, 0, 0, 2), wan_gw_mac);

    std::cout << "[INFO] Topology initialized with 2 interfaces and 3 routing entries.\n";
    std::cout << "       - Direct Subnet: 192.168.1.0/24 -> Gi0/0/0\n";
    std::cout << "       - Direct Subnet: 10.0.0.0/30    -> Gi0/0/1\n";
    std::cout << "       - LPM Route:     172.16.0.0/16  -> via 10.0.0.2 on Gi0/0/1\n";
    std::cout << "       - Default Route: 0.0.0.0/0      -> via 10.0.0.2 on Gi0/0/1\n\n";

    std::vector<router::packet_buffer_t> tx_packets;

    // ------------------------------------------------------------------------
    // Scenario 1: Forwarding IPv4 packet matching LPM route (172.16.5.10)
    // ------------------------------------------------------------------------
    std::cout << ">>> Scenario 1: Forwarding IPv4 packet to 172.16.5.10 (LPM /16 match)\n";
    router::packet_buffer_t pkt1;
    pkt1.ingress_interface_id = iface1.id;
    size_t l2_len = router::create_ethernet_header(
        pkt1.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33), router::ETHERTYPE_IPV4);
    uint8_t payload[32] = "Hello High-Performance Router!";
    size_t l3_len = router::create_ipv4_header(
        pkt1.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(172, 16, 5, 10),
        router::IPPROTO_UDP_V, sizeof(payload), 64);
    std::memcpy(pkt1.data + l2_len + l3_len, payload, sizeof(payload));
    pkt1.length = l2_len + l3_len + sizeof(payload);

    tx_packets.clear();
    router.process_packet(pkt1, tx_packets);
    std::cout << "    Forwarded packets produced: " << tx_packets.size() << "\n";
    if (!tx_packets.empty()) {
        auto eth = router::parse_ethernet_frame(tx_packets[0].data, tx_packets[0].length);
        auto ip = router::parse_ipv4_packet(tx_packets[0].data + eth.l3_offset, eth.l3_length);
        std::cout << "    Egress interface: " << tx_packets[0].egress_interface_id
                  << ", New Dst MAC: " << eth.dst_mac.to_string()
                  << ", Decremented TTL: " << static_cast<int>(ip.ttl) << "\n";
    }

    // ------------------------------------------------------------------------
    // Scenario 2: TTL Expiration (TTL = 1)
    // ------------------------------------------------------------------------
    std::cout << "\n>>> Scenario 2: Testing TTL Expiration (TTL = 1 incoming)\n";
    router::packet_buffer_t pkt2;
    pkt2.ingress_interface_id = iface1.id;
    l2_len = router::create_ethernet_header(
        pkt2.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33), router::ETHERTYPE_IPV4);
    l3_len = router::create_ipv4_header(
        pkt2.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(172, 16, 5, 10),
        router::IPPROTO_UDP_V, sizeof(payload), 1 /* TTL = 1 */);
    std::memcpy(pkt2.data + l2_len + l3_len, payload, sizeof(payload));
    pkt2.length = l2_len + l3_len + sizeof(payload);

    tx_packets.clear();
    router.process_packet(pkt2, tx_packets);
    std::cout << "    Forwarded packets produced: " << tx_packets.size()
              << " (Expected 0 - TTL expired)\n";

    // ------------------------------------------------------------------------
    // Scenario 3: ARP Resolution and Pending Packet Buffering
    // ------------------------------------------------------------------------
    std::cout << "\n>>> Scenario 3: Packet to unresolved neighbor 192.168.1.50 (ARP Pending Queue)\n";
    router::packet_buffer_t pkt3;
    pkt3.ingress_interface_id = iface2.id;
    l2_len = router::create_ethernet_header(
        pkt3.data, router::MAX_PACKET_SIZE, iface2.mac_addr,
        wan_gw_mac, router::ETHERTYPE_IPV4);
    l3_len = router::create_ipv4_header(
        pkt3.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(8, 8, 8, 8), router::ipv4_address_t(192, 168, 1, 50),
        router::IPPROTO_UDP_V, sizeof(payload), 64);
    std::memcpy(pkt3.data + l2_len + l3_len, payload, sizeof(payload));
    pkt3.length = l2_len + l3_len + sizeof(payload);

    tx_packets.clear();
    router.process_packet(pkt3, tx_packets);
    std::cout << "    Packets produced on cache miss: " << tx_packets.size() << "\n";
    if (!tx_packets.empty()) {
        auto eth = router::parse_ethernet_frame(tx_packets[0].data, tx_packets[0].length);
        std::cout << "    Triggered ARP Request frame: EtherType 0x" << std::hex << eth.ethertype << std::dec
                  << " to broadcast MAC " << eth.dst_mac.to_string() << "\n";
    }

    std::cout << "    Now receiving ARP Reply from host 192.168.1.50...\n";
    router::packet_buffer_t arp_reply;
    arp_reply.ingress_interface_id = iface1.id;
    router::mac_address_t host_mac(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
    size_t arp_len = router::create_arp_reply_frame(
        arp_reply.data, router::MAX_PACKET_SIZE, host_mac, router::ipv4_address_t(192, 168, 1, 50),
        iface1.mac_addr, iface1.ip_addr);
    arp_reply.length = arp_len;

    tx_packets.clear();
    router.process_packet(arp_reply, tx_packets);
    std::cout << "    Packets dequeued and forwarded upon ARP resolution: " << tx_packets.size() << "\n";
    if (!tx_packets.empty()) {
        auto eth = router::parse_ethernet_frame(tx_packets[0].data, tx_packets[0].length);
        std::cout << "    Buffered packet successfully forwarded to host MAC: "
                  << eth.dst_mac.to_string() << "\n";
    }

    // ------------------------------------------------------------------------
    // Scenario 4: IEEE 802.1Q VLAN Tagged Frame Processing
    // ------------------------------------------------------------------------
    std::cout << "\n>>> Scenario 4: IEEE 802.1Q VLAN tagged frame processing (VLAN ID 100)\n";
    router::packet_buffer_t vlan_pkt;
    vlan_pkt.ingress_interface_id = iface1.id;
    l2_len = router::create_ethernet_header(
        vlan_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33),
        router::ETHERTYPE_IPV4, 100 /* VLAN ID */);
    l3_len = router::create_ipv4_header(
        vlan_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(172, 16, 5, 10),
        router::IPPROTO_UDP_V, sizeof(payload), 64);
    std::memcpy(vlan_pkt.data + l2_len + l3_len, payload, sizeof(payload));
    vlan_pkt.length = l2_len + l3_len + sizeof(payload);

    tx_packets.clear();
    router.process_packet(vlan_pkt, tx_packets);
    std::cout << "    VLAN tagged frame processed and forwarded: " << tx_packets.size() << "\n";

    // Scenario 5: Checksum Corruption Rejection
    std::cout << "\n>>> Scenario 5: Checksum Corruption Detection\n";
    router::packet_buffer_t bad_cksum_pkt;
    bad_cksum_pkt.ingress_interface_id = iface1.id;
    l2_len = router::create_ethernet_header(
        bad_cksum_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33), router::ETHERTYPE_IPV4);
    l3_len = router::create_ipv4_header(
        bad_cksum_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(172, 16, 5, 10),
        router::IPPROTO_UDP_V, sizeof(payload), 64);
    std::memcpy(bad_cksum_pkt.data + l2_len + l3_len, payload, sizeof(payload));
    bad_cksum_pkt.length = l2_len + l3_len + sizeof(payload);

    bad_cksum_pkt.data[l2_len + 10] ^= 0xFF; // Corrupt checksum byte
    tx_packets.clear();
    router.process_packet(bad_cksum_pkt, tx_packets);
    std::cout << "    Corrupted checksum packet dropped: " << (tx_packets.empty() ? "YES" : "NO") << "\n";

    print_statistics(router.stats());
}

void run_live_mode(const std::string& ifname) {
    if (ifname.empty()) {
        std::cerr << "[ERROR] Interface name must be specified via --interface <ifname> for live mode.\n";
        return;
    }

    if (!router::AfPacketIO::check_privileges()) {
        std::cerr << "\n[PERMISSION ERROR] Live AF_PACKET packet I/O requires root execution (CAP_NET_RAW).\n"
                  << "Please run: sudo ./router_app --live --interface " << ifname << "\n";
        return;
    }

    std::cout << "[WARNING] Entering Live AF_PACKET Mode on interface '" << ifname << "'.\n";
    std::cout << "          Press Ctrl+C to stop.\n\n";

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    router::PacketForwarder router;
    router::AfPacketIO io(ifname, 1);

    if (!io.open()) {
        std::cerr << "[ERROR] Failed to open AF_PACKET socket.\n";
        return;
    }

    router::packet_buffer_t rx_pkt;
    std::vector<router::packet_buffer_t> tx_pkts;

    auto last_stats_time = std::chrono::steady_clock::now();

    while (g_running) {
        if (io.receive(rx_pkt)) {
            tx_pkts.clear();
            if (router.process_packet(rx_pkt, tx_pkts)) {
                for (const auto& tx_pkt : tx_pkts) {
                    io.transmit(tx_pkt);
                }
            }
        } else {
            // Sleep briefly to yield CPU when idle in non-blocking loop
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }

        auto now = std::chrono::steady_clock::now();
        if (now - last_stats_time >= std::chrono::seconds(2)) {
            router.periodic_maintenance();
            last_stats_time = now;
        }
    }

    io.close();
    std::cout << "\n[INFO] Stopped live forwarding.\n";
    print_statistics(router.stats());
}

int main(int argc, char** argv) {
    print_banner();

    bool live_mode = false;
    std::string ifname;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--live") {
            live_mode = true;
        } else if (arg == "--interface" && i + 1 < argc) {
            ifname = argv[++i];
        } else if (arg == "--offline") {
            live_mode = false;
        } else if (arg == "--benchmark") {
            std::cout << "Please use dedicated benchmark binary: ./router_benchmark\n";
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_help(argv[0]);
            return 1;
        }
    }

    if (live_mode) {
        run_live_mode(ifname);
    } else {
        run_offline_simulation();
    }

    return 0;
}
