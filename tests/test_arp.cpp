#include <gtest/gtest.h>
#include "router/arp.h"
#include <thread>

TEST(ArpTest, ParseAndCreateArpRequest) {
    uint8_t buffer[64] = {0};
    router::mac_address_t sender_mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    router::ipv4_address_t sender_ip(192, 168, 1, 1);
    router::ipv4_address_t target_ip(192, 168, 1, 100);

    size_t frame_len = router::create_arp_request_frame(
        buffer, sizeof(buffer), sender_mac, sender_ip, target_ip);
    EXPECT_GE(frame_len, 42);

    // Parse L2 header first
    EXPECT_EQ(buffer[12], 0x08);
    EXPECT_EQ(buffer[13], 0x06); // ARP EtherType

    // Parse ARP Payload
    auto res = router::parse_arp_packet(buffer + 14, frame_len - 14);
    EXPECT_EQ(res.error, router::arp_error_t::SUCCESS);
    EXPECT_EQ(res.opcode, router::ARP_OP_REQUEST);
    EXPECT_EQ(res.sender_mac, sender_mac);
    EXPECT_EQ(res.sender_ip, sender_ip);
    EXPECT_EQ(res.target_ip, target_ip);
    EXPECT_TRUE(res.target_mac.is_zero());
}

TEST(ArpTest, ParseAndCreateArpReply) {
    uint8_t buffer[64] = {0};
    router::mac_address_t sender_mac(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    router::ipv4_address_t sender_ip(192, 168, 1, 100);
    router::mac_address_t target_mac(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    router::ipv4_address_t target_ip(192, 168, 1, 1);

    size_t frame_len = router::create_arp_reply_frame(
        buffer, sizeof(buffer), sender_mac, sender_ip, target_mac, target_ip);
    EXPECT_GE(frame_len, 42);

    auto res = router::parse_arp_packet(buffer + 14, frame_len - 14);
    EXPECT_EQ(res.error, router::arp_error_t::SUCCESS);
    EXPECT_EQ(res.opcode, router::ARP_OP_REPLY);
    EXPECT_EQ(res.sender_mac, sender_mac);
    EXPECT_EQ(res.sender_ip, sender_ip);
    EXPECT_EQ(res.target_mac, target_mac);
    EXPECT_EQ(res.target_ip, target_ip);
}

TEST(ArpTest, MalformedArpPackets) {
    uint8_t buf[20] = {0};
    auto res = router::parse_arp_packet(buf, sizeof(buf));
    EXPECT_EQ(res.error, router::arp_error_t::PACKET_TOO_SHORT);

    uint8_t full_buf[28] = {0};
    full_buf[0] = 0x00; full_buf[1] = 0x02; // Invalid hardware type (!= 1)
    res = router::parse_arp_packet(full_buf, sizeof(full_buf));
    EXPECT_EQ(res.error, router::arp_error_t::UNSUPPORTED_HARDWARE_TYPE);
}

TEST(ArpTest, CacheResolutionAndExpiration) {
    router::ArpCache cache(std::chrono::seconds(1)); // 1s TTL for testing

    router::ipv4_address_t ip(10, 0, 0, 5);
    router::mac_address_t mac(1, 2, 3, 4, 5, 6);

    router::mac_address_t resolved;
    EXPECT_FALSE(cache.resolve(ip, &resolved));

    cache.update(ip, mac, router::arp_entry_state_t::REACHABLE, std::chrono::seconds(1));
    EXPECT_TRUE(cache.resolve(ip, &resolved));
    EXPECT_EQ(resolved, mac);

    // Sleep past expiration
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_FALSE(cache.resolve(ip, &resolved));

    // Sweep should clean up expired entry
    auto sweep_res = cache.sweep();
    EXPECT_EQ(sweep_res.first, 1); // 1 entry expired
    EXPECT_EQ(cache.size(), 0);
}

TEST(ArpTest, PendingPacketBufferingAndFlush) {
    router::ArpCache cache;

    router::ipv4_address_t target_ip(192, 168, 1, 50);

    router::packet_buffer_t pkt1;
    pkt1.data[0] = 0x11;
    pkt1.length = 60;

    router::packet_buffer_t pkt2;
    pkt2.data[0] = 0x22;
    pkt2.length = 70;

    EXPECT_TRUE(cache.queue_pending_packet(target_ip, pkt1));
    EXPECT_TRUE(cache.queue_pending_packet(target_ip, pkt2));
    EXPECT_EQ(cache.pending_packet_count(), 2);

    // Dequeue for another IP should be empty
    auto empty = cache.dequeue_pending_packets(router::ipv4_address_t(192, 168, 1, 99));
    EXPECT_TRUE(empty.empty());

    // Dequeue for target IP
    auto flushed = cache.dequeue_pending_packets(target_ip);
    ASSERT_EQ(flushed.size(), 2);
    EXPECT_EQ(flushed[0].data[0], 0x11);
    EXPECT_EQ(flushed[1].data[0], 0x22);
    EXPECT_EQ(cache.pending_packet_count(), 0);
}

TEST(ArpTest, PendingQueueLimits) {
    router::ArpCache cache(std::chrono::seconds(300), 2 /* max 2 per IP */, 5 /* max 5 total */);

    router::ipv4_address_t target_ip(10, 0, 0, 1);

    router::packet_buffer_t pkt;
    pkt.length = 60;

    pkt.data[0] = 1;
    cache.queue_pending_packet(target_ip, pkt);
    pkt.data[0] = 2;
    cache.queue_pending_packet(target_ip, pkt);
    pkt.data[0] = 3; // Should drop packet 1
    cache.queue_pending_packet(target_ip, pkt);

    auto flushed = cache.dequeue_pending_packets(target_ip);
    ASSERT_EQ(flushed.size(), 2);
    EXPECT_EQ(flushed[0].data[0], 2);
    EXPECT_EQ(flushed[1].data[0], 3);
}
