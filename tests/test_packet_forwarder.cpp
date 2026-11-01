#include <gtest/gtest.h>
#include "router/packet_forwarder.h"
#include "router/ethernet.h"
#include "router/ipv4.h"
#include "router/arp.h"

class PacketForwarderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Interface 1 (LAN)
        iface1.id = 1;
        iface1.name = "eth0";
        iface1.mac_addr = router::mac_address_t(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        iface1.ip_addr = router::ipv4_address_t(192, 168, 1, 1);
        iface1.netmask = router::ipv4_address_t(255, 255, 255, 0);
        iface1.mtu = 1500;
        iface1.is_up = true;
        router.add_interface(iface1);

        // Interface 2 (WAN)
        iface2.id = 2;
        iface2.name = "eth1";
        iface2.mac_addr = router::mac_address_t(0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE);
        iface2.ip_addr = router::ipv4_address_t(10, 0, 0, 1);
        iface2.netmask = router::ipv4_address_t(255, 255, 255, 252);
        iface2.mtu = 1500;
        iface2.is_up = true;
        router.add_interface(iface2);
    }

    router::PacketForwarder router;
    router::network_interface_t iface1;
    router::network_interface_t iface2;
};

TEST_F(PacketForwarderTest, SuccessfulForwardingWithPrepopulatedArp) {
    // Populate ARP cache for WAN next-hop 10.0.0.2
    router::mac_address_t next_hop_mac(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
    router.arp_cache().update(router::ipv4_address_t(10, 0, 0, 2), next_hop_mac);

    // Build incoming IPv4 packet on iface1 (from 192.168.1.100 to 10.0.0.2)
    router::packet_buffer_t rx_pkt;
    rx_pkt.ingress_interface_id = iface1.id;

    size_t l2_len = router::create_ethernet_header(
        rx_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03), router::ETHERTYPE_IPV4);

    size_t l3_len = router::create_ipv4_header(
        rx_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(10, 0, 0, 2),
        router::IPPROTO_UDP_V, 20, 64);

    rx_pkt.length = l2_len + l3_len + 20;

    std::vector<router::packet_buffer_t> tx_pkts;
    EXPECT_TRUE(router.process_packet(rx_pkt, tx_pkts));

    ASSERT_EQ(tx_pkts.size(), 1);
    const auto& tx_pkt = tx_pkts[0];
    EXPECT_EQ(tx_pkt.egress_interface_id, iface2.id);

    // Verify rewritten Ethernet header
    auto eth_res = router::parse_ethernet_frame(tx_pkt.data, tx_pkt.length);
    EXPECT_EQ(eth_res.error, router::ethernet_error_t::SUCCESS);
    EXPECT_EQ(eth_res.dst_mac, next_hop_mac);
    EXPECT_EQ(eth_res.src_mac, iface2.mac_addr);

    // Verify IPv4 header modifications (TTL decremented & checksum valid)
    auto ip_res = router::parse_ipv4_packet(tx_pkt.data + eth_res.l3_offset, eth_res.l3_length);
    EXPECT_EQ(ip_res.error, router::ipv4_error_t::SUCCESS);
    EXPECT_EQ(ip_res.ttl, 63);

    // Stats verification
    EXPECT_EQ(router.stats().rx_packets, 1);
    EXPECT_EQ(router.stats().tx_packets, 1);
    EXPECT_EQ(router.stats().l3_forwarded, 1);
    EXPECT_EQ(router.stats().arp_cache_hits, 1);
}

TEST_F(PacketForwarderTest, TtlExpirationDrop) {
    router::mac_address_t next_hop_mac(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
    router.arp_cache().update(router::ipv4_address_t(10, 0, 0, 2), next_hop_mac);

    router::packet_buffer_t rx_pkt;
    rx_pkt.ingress_interface_id = iface1.id;

    size_t l2_len = router::create_ethernet_header(
        rx_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03), router::ETHERTYPE_IPV4);

    // Packet with TTL = 1
    size_t l3_len = router::create_ipv4_header(
        rx_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(10, 0, 0, 2),
        router::IPPROTO_UDP_V, 20, 1 /* TTL = 1 */);

    rx_pkt.length = l2_len + l3_len + 20;

    std::vector<router::packet_buffer_t> tx_pkts;
    EXPECT_FALSE(router.process_packet(rx_pkt, tx_pkts));
    EXPECT_TRUE(tx_pkts.empty());
    EXPECT_EQ(router.stats().l3_ttl_expired, 1);
}

TEST_F(PacketForwarderTest, ArpMissBufferingAndReplyResolution) {
    // ARP cache is initially empty for 10.0.0.2
    router::packet_buffer_t rx_pkt;
    rx_pkt.ingress_interface_id = iface1.id;

    size_t l2_len = router::create_ethernet_header(
        rx_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03), router::ETHERTYPE_IPV4);

    size_t l3_len = router::create_ipv4_header(
        rx_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(10, 0, 0, 2),
        router::IPPROTO_UDP_V, 20, 64);

    rx_pkt.length = l2_len + l3_len + 20;

    std::vector<router::packet_buffer_t> tx_pkts;
    EXPECT_TRUE(router.process_packet(rx_pkt, tx_pkts));

    // Must generate 1 packet: an ARP Request for 10.0.0.2
    ASSERT_EQ(tx_pkts.size(), 1);
    EXPECT_EQ(router.stats().arp_cache_misses, 1);
    EXPECT_EQ(router.stats().arp_pending_queued, 1);
    EXPECT_EQ(router.stats().arp_requests_sent, 1);

    auto arp_req_res = router::parse_ethernet_frame(tx_pkts[0].data, tx_pkts[0].length);
    EXPECT_EQ(arp_req_res.ethertype, router::ETHERTYPE_ARP);
    EXPECT_TRUE(arp_req_res.dst_mac.is_broadcast());

    // Now inject ARP Reply from 10.0.0.2
    router::packet_buffer_t arp_reply;
    arp_reply.ingress_interface_id = iface2.id;
    router::mac_address_t host_mac(0x52, 0x54, 0x00, 0x99, 0x88, 0x77);
    size_t reply_len = router::create_arp_reply_frame(
        arp_reply.data, router::MAX_PACKET_SIZE, host_mac, router::ipv4_address_t(10, 0, 0, 2),
        iface2.mac_addr, iface2.ip_addr);
    arp_reply.length = reply_len;

    tx_pkts.clear();
    EXPECT_TRUE(router.process_packet(arp_reply, tx_pkts));

    // The queued packet should now be forwarded!
    ASSERT_EQ(tx_pkts.size(), 1);
    EXPECT_EQ(router.stats().arp_pending_dequeued, 1);
    EXPECT_EQ(router.stats().l3_forwarded, 1);

    auto fwd_eth = router::parse_ethernet_frame(tx_pkts[0].data, tx_pkts[0].length);
    EXPECT_EQ(fwd_eth.dst_mac, host_mac);
}

TEST_F(PacketForwarderTest, RespondToArpRequestForRouterIp) {
    router::packet_buffer_t rx_arp;
    rx_arp.ingress_interface_id = iface1.id;

    router::mac_address_t host_mac(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    router::ipv4_address_t host_ip(192, 168, 1, 88);

    size_t len = router::create_arp_request_frame(
        rx_arp.data, router::MAX_PACKET_SIZE, host_mac, host_ip, iface1.ip_addr);
    rx_arp.length = len;

    std::vector<router::packet_buffer_t> tx_pkts;
    EXPECT_TRUE(router.process_packet(rx_arp, tx_pkts));

    ASSERT_EQ(tx_pkts.size(), 1);
    EXPECT_EQ(router.stats().arp_requests_received, 1);
    EXPECT_EQ(router.stats().arp_replies_sent, 1);

    auto reply_eth = router::parse_ethernet_frame(tx_pkts[0].data, tx_pkts[0].length);
    EXPECT_EQ(reply_eth.dst_mac, host_mac);
    EXPECT_EQ(reply_eth.src_mac, iface1.mac_addr);

    auto reply_arp = router::parse_arp_packet(tx_pkts[0].data + 14, tx_pkts[0].length - 14);
    EXPECT_EQ(reply_arp.opcode, router::ARP_OP_REPLY);
    EXPECT_EQ(reply_arp.sender_mac, iface1.mac_addr);
    EXPECT_EQ(reply_arp.sender_ip, iface1.ip_addr);
}

TEST_F(PacketForwarderTest, LocalDeliveryWhenDstIsRouterIp) {
    router::packet_buffer_t rx_pkt;
    rx_pkt.ingress_interface_id = iface1.id;

    size_t l2_len = router::create_ethernet_header(
        rx_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03), router::ETHERTYPE_IPV4);

    size_t l3_len = router::create_ipv4_header(
        rx_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), iface1.ip_addr, // Targeted at router itself
        router::IPPROTO_ICMP_V, 32, 64);

    rx_pkt.length = l2_len + l3_len + 32;

    std::vector<router::packet_buffer_t> tx_pkts;
    EXPECT_TRUE(router.process_packet(rx_pkt, tx_pkts));
    EXPECT_TRUE(tx_pkts.empty()); // Local delivery consumes packet
    EXPECT_EQ(router.stats().l3_local_delivered, 1);
}
