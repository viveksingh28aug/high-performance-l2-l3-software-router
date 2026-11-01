#include <gtest/gtest.h>
#include "router/ethernet.h"
#include "router/ipv4.h"
#include "router/arp.h"
#include "router/packet_forwarder.h"
#include <vector>
#include <random>

TEST(MalformedTest, NullPointerSafety) {
    auto eth_res = router::parse_ethernet_frame(nullptr, 100);
    EXPECT_EQ(eth_res.error, router::ethernet_error_t::INVALID_ARGUMENT);

    auto ip_res = router::parse_ipv4_packet(nullptr, 100);
    EXPECT_EQ(ip_res.error, router::ipv4_error_t::INVALID_ARGUMENT);

    auto arp_res = router::parse_arp_packet(nullptr, 100);
    EXPECT_EQ(arp_res.error, router::arp_error_t::INVALID_ARGUMENT);

    EXPECT_FALSE(router::decrement_ipv4_ttl(nullptr, 100));
    EXPECT_FALSE(router::recalculate_ipv4_checksum(nullptr, 100));
}

TEST(MalformedTest, FrameBoundaryConditions) {
    uint8_t buffer[2048] = {0};

    // Test all frame lengths from 0 to 30
    for (size_t len = 0; len < 14; ++len) {
        auto res = router::parse_ethernet_frame(buffer, len);
        EXPECT_EQ(res.error, router::ethernet_error_t::FRAME_TOO_SHORT);
    }

    // Set EtherType to 802.1Q VLAN (0x8100)
    buffer[12] = 0x81;
    buffer[13] = 0x00;
    for (size_t len = 14; len < 18; ++len) {
        auto res = router::parse_ethernet_frame(buffer, len);
        EXPECT_EQ(res.error, router::ethernet_error_t::TRUNCATED_VLAN_TAG);
    }
}

TEST(MalformedTest, RandomFuzzingNoCrashes) {
    router::PacketForwarder router;
    router::network_interface_t iface;
    iface.id = 1;
    iface.name = "fuzz0";
    iface.mac_addr = router::mac_address_t(0, 1, 2, 3, 4, 5);
    iface.ip_addr = router::ipv4_address_t(10, 0, 0, 1);
    iface.netmask = router::ipv4_address_t(255, 255, 255, 0);
    router.add_interface(iface);

    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> len_dist(0, 1600);
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);

    std::vector<router::packet_buffer_t> tx_pkts;

    // Run 5,000 randomized corrupted frames
    for (int i = 0; i < 5000; ++i) {
        router::packet_buffer_t pkt;
        pkt.ingress_interface_id = iface.id;
        pkt.length = static_cast<size_t>(len_dist(rng));
        for (size_t j = 0; j < pkt.length; ++j) {
            pkt.data[j] = byte_dist(rng);
        }

        tx_pkts.clear();
        // Must never crash or trigger sanitizer exceptions
        router.process_packet(pkt, tx_pkts);
    }

    EXPECT_GT(router.stats().rx_packets, 0);
}
