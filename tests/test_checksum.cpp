#include <gtest/gtest.h>
#include "router/checksum.h"
#include "router/ipv4.h"
#include <vector>
#include <random>

TEST(ChecksumTest, BasicCalculationAndVerification) {
    // Standard 20-byte IPv4 header bytes (with checksum initialized to 0)
    uint8_t header[20] = {
        0x45, 0x00, 0x00, 0x3c, // Version=4, IHL=5, Total Len=60
        0x1c, 0x46, 0x40, 0x00, // ID, Flags=DF, Frag Offset=0
        0x40, 0x06, 0x00, 0x00, // TTL=64, Proto=6 (TCP), Checksum=0
        0xac, 0x10, 0x0a, 0x63, // Src: 172.16.10.99
        0xac, 0x10, 0x0a, 0x0c  // Dst: 172.16.10.12
    };

    uint16_t cksum = router::calculate_checksum(header, sizeof(header));
    EXPECT_NE(cksum, 0);

    // Embed checksum back into header
    std::memcpy(header + 10, &cksum, sizeof(cksum));

    // Verification should now succeed
    EXPECT_TRUE(router::verify_checksum(header, sizeof(header)));

    // Corrupt one bit
    header[5] ^= 0x01;
    EXPECT_FALSE(router::verify_checksum(header, sizeof(header)));
}

TEST(ChecksumTest, OddByteLength) {
    uint8_t buffer[7] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    uint16_t cksum = router::calculate_checksum(buffer, sizeof(buffer));
    EXPECT_NE(cksum, 0);

    // Padding with zero byte explicitly to 8 bytes should yield same checksum
    uint8_t padded[8] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0x00};
    uint16_t cksum_padded = router::calculate_checksum(padded, sizeof(padded));
    EXPECT_EQ(cksum, cksum_padded);
}

TEST(ChecksumTest, IncrementalUpdateVsFullRecalculation) {
    // Generate headers with random fields, decrement TTL, and compare RFC 1624 incremental update with RFC 1071
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> ip_dist;
    std::uniform_int_distribution<uint8_t> ttl_dist(2, 255);
    std::uniform_int_distribution<uint8_t> proto_dist(1, 255);

    for (int iter = 0; iter < 1000; ++iter) {
        uint8_t header[20];
        router::ipv4_address_t src(ip_dist(rng));
        router::ipv4_address_t dst(ip_dist(rng));
        uint8_t ttl = ttl_dist(rng);
        uint8_t proto = proto_dist(rng);

        size_t len = router::create_ipv4_header(header, sizeof(header), src, dst, proto, 40, ttl, 1234);
        ASSERT_EQ(len, 20);
        ASSERT_TRUE(router::verify_checksum(header, 20));

        uint16_t orig_cksum;
        std::memcpy(&orig_cksum, header + 10, 2);

        // Incremental update
        uint8_t new_ttl = ttl - 1;
        uint16_t incremental_cksum = router::checksum_update_ttl(orig_cksum, ttl, new_ttl, proto);

        // Full recalculation
        header[8] = new_ttl;
        header[10] = 0;
        header[11] = 0;
        uint16_t full_cksum = router::calculate_checksum(header, 20);

        EXPECT_EQ(incremental_cksum, full_cksum) << "Failed on iteration " << iter
            << " TTL: " << (int)ttl << " -> " << (int)new_ttl << " proto: " << (int)proto;
    }
}
