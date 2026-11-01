#include <gtest/gtest.h>
#include "router/ipv4.h"
#include "router/checksum.h"
#include <arpa/inet.h>

TEST(IPv4Test, AddressParsingAndFormatting) {
    router::ipv4_address_t ip1(192, 168, 1, 100);
    EXPECT_EQ(ip1.to_string(), "192.168.1.100");

    auto ip2 = router::ipv4_address_t::from_string("192.168.1.100");
    EXPECT_EQ(ip1, ip2);

    auto loopback = router::ipv4_address_t::from_string("127.0.0.1");
    EXPECT_TRUE(loopback.is_loopback());

    auto mcast = router::ipv4_address_t::from_string("224.0.0.1");
    EXPECT_TRUE(mcast.is_multicast());

    auto bcast = router::ipv4_address_t::broadcast();
    EXPECT_TRUE(bcast.is_broadcast());
}

TEST(IPv4Test, ValidHeaderParsing) {
    uint8_t buffer[64] = {0};
    router::ipv4_address_t src(10, 0, 0, 1);
    router::ipv4_address_t dst(10, 0, 0, 2);

    size_t hdr_len = router::create_ipv4_header(
        buffer, sizeof(buffer), src, dst, router::IPPROTO_TCP_V, 20, 64, 4321);
    EXPECT_EQ(hdr_len, 20);

    auto res = router::parse_ipv4_packet(buffer, 40);
    EXPECT_EQ(res.error, router::ipv4_error_t::SUCCESS);
    EXPECT_EQ(res.version, 4);
    EXPECT_EQ(res.ihl_bytes, 20);
    EXPECT_EQ(res.total_length, 40);
    EXPECT_EQ(res.ttl, 64);
    EXPECT_EQ(res.protocol, router::IPPROTO_TCP_V);
    EXPECT_EQ(res.src_ip, src);
    EXPECT_EQ(res.dst_ip, dst);
    EXPECT_TRUE(res.df);
    EXPECT_FALSE(res.mf);
    EXPECT_EQ(res.fragment_offset, 0);
    EXPECT_FALSE(res.is_fragmented);
    EXPECT_EQ(res.payload_offset, 20);
    EXPECT_EQ(res.payload_length, 20);
}

TEST(IPv4Test, ChecksumCorruption) {
    uint8_t buffer[64] = {0};
    router::create_ipv4_header(
        buffer, sizeof(buffer), router::ipv4_address_t(1, 2, 3, 4),
        router::ipv4_address_t(5, 6, 7, 8), router::IPPROTO_UDP_V, 20, 64);

    // Corrupt checksum byte
    buffer[10] ^= 0x55;

    auto res = router::parse_ipv4_packet(buffer, 40);
    EXPECT_EQ(res.error, router::ipv4_error_t::CHECKSUM_ERROR);
}

TEST(IPv4Test, InvalidVersionAndIhl) {
    uint8_t buffer[64] = {0};
    router::create_ipv4_header(
        buffer, sizeof(buffer), router::ipv4_address_t(1, 1, 1, 1),
        router::ipv4_address_t(2, 2, 2, 2), router::IPPROTO_TCP_V, 20, 64);

    // Test Invalid Version (e.g. 6)
    buffer[0] = (6 << 4) | 5;
    router::recalculate_ipv4_checksum(buffer, 40);
    auto res = router::parse_ipv4_packet(buffer, 40);
    EXPECT_EQ(res.error, router::ipv4_error_t::INVALID_VERSION);

    // Test Invalid IHL (< 5)
    buffer[0] = (4 << 4) | 4;
    router::recalculate_ipv4_checksum(buffer, 40);
    res = router::parse_ipv4_packet(buffer, 40);
    EXPECT_EQ(res.error, router::ipv4_error_t::INVALID_IHL);
}

TEST(IPv4Test, LengthValidation) {
    uint8_t buffer[64] = {0};
    router::create_ipv4_header(
        buffer, sizeof(buffer), router::ipv4_address_t(1, 1, 1, 1),
        router::ipv4_address_t(2, 2, 2, 2), router::IPPROTO_TCP_V, 20, 64);

    // Buffer smaller than total_length (truncated packet)
    auto res = router::parse_ipv4_packet(buffer, 30); // Header says total_length is 40
    EXPECT_EQ(res.error, router::ipv4_error_t::PACKET_TRUNCATED);

    // Header too short
    res = router::parse_ipv4_packet(buffer, 15);
    EXPECT_EQ(res.error, router::ipv4_error_t::HEADER_TOO_SHORT);
}

TEST(IPv4Test, TtlDecrementAndExpiration) {
    uint8_t buffer[64] = {0};
    router::create_ipv4_header(
        buffer, sizeof(buffer), router::ipv4_address_t(10, 1, 1, 1),
        router::ipv4_address_t(10, 2, 2, 2), router::IPPROTO_UDP_V, 10, 64);

    uint8_t new_ttl = 0;
    EXPECT_TRUE(router::decrement_ipv4_ttl(buffer, 30, &new_ttl));
    EXPECT_EQ(new_ttl, 63);
    EXPECT_EQ(buffer[8], 63);

    // Verify incremental checksum matches RFC 1071
    EXPECT_TRUE(router::verify_checksum(buffer, 20));

    // Test TTL = 1 expiration
    buffer[8] = 1;
    router::recalculate_ipv4_checksum(buffer, 30);
    EXPECT_FALSE(router::decrement_ipv4_ttl(buffer, 30, &new_ttl));
    EXPECT_EQ(buffer[8], 1); // Remains untouched
}

TEST(IPv4Test, FragmentationParsing) {
    uint8_t buffer[64] = {0};
    router::create_ipv4_header(
        buffer, sizeof(buffer), router::ipv4_address_t(1, 1, 1, 1),
        router::ipv4_address_t(2, 2, 2, 2), router::IPPROTO_UDP_V, 20, 64);

    // Set MF = 1, fragment offset = 100 (800 bytes)
    uint16_t flags_fo = htons(0x2000 | 100);
    std::memcpy(buffer + 6, &flags_fo, 2);
    router::recalculate_ipv4_checksum(buffer, 40);

    auto res = router::parse_ipv4_packet(buffer, 40);
    EXPECT_EQ(res.error, router::ipv4_error_t::SUCCESS);
    EXPECT_TRUE(res.mf);
    EXPECT_FALSE(res.df);
    EXPECT_EQ(res.fragment_offset, 100);
    EXPECT_TRUE(res.is_fragmented);
    EXPECT_FALSE(res.is_first_fragment);
}
