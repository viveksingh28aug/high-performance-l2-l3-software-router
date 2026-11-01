#include <gtest/gtest.h>
#include "router/ethernet.h"

TEST(EthernetTest, MacAddressOperations) {
    router::mac_address_t mac1(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
    EXPECT_EQ(mac1.to_string(), "aa:bb:cc:dd:ee:ff");

    auto mac2 = router::mac_address_t::from_string("aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(mac1, mac2);

    auto mac_hyphen = router::mac_address_t::from_string("aa-bb-cc-dd-ee-ff");
    EXPECT_EQ(mac1, mac_hyphen);

    auto bcast = router::mac_address_t::broadcast();
    EXPECT_TRUE(bcast.is_broadcast());
    EXPECT_TRUE(bcast.is_multicast());

    auto zero = router::mac_address_t::zero();
    EXPECT_TRUE(zero.is_zero());
    EXPECT_FALSE(zero.is_multicast());

    router::mac_address_t mcast(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01);
    EXPECT_TRUE(mcast.is_multicast());
    EXPECT_FALSE(mcast.is_broadcast());
}

TEST(EthernetTest, ParseUntaggedEthernetFrame) {
    uint8_t buffer[64];
    router::mac_address_t dst(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    router::mac_address_t src(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    size_t hdr_len = router::create_ethernet_header(
        buffer, sizeof(buffer), dst, src, router::ETHERTYPE_IPV4);
    EXPECT_EQ(hdr_len, 14);

    auto res = router::parse_ethernet_frame(buffer, sizeof(buffer));
    EXPECT_EQ(res.error, router::ethernet_error_t::SUCCESS);
    EXPECT_EQ(res.dst_mac, dst);
    EXPECT_EQ(res.src_mac, src);
    EXPECT_EQ(res.ethertype, router::ETHERTYPE_IPV4);
    EXPECT_FALSE(res.has_vlan);
    EXPECT_EQ(res.l3_offset, 14);
    EXPECT_EQ(res.l3_length, 50);
}

TEST(EthernetTest, ParseVlanTaggedFrame) {
    uint8_t buffer[64];
    router::mac_address_t dst(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    router::mac_address_t src(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    size_t hdr_len = router::create_ethernet_header(
        buffer, sizeof(buffer), dst, src, router::ETHERTYPE_IPV4, 250 /* VLAN ID */);
    EXPECT_EQ(hdr_len, 18);

    auto res = router::parse_ethernet_frame(buffer, sizeof(buffer));
    EXPECT_EQ(res.error, router::ethernet_error_t::SUCCESS);
    EXPECT_EQ(res.dst_mac, dst);
    EXPECT_EQ(res.src_mac, src);
    EXPECT_EQ(res.ethertype, router::ETHERTYPE_IPV4);
    EXPECT_TRUE(res.has_vlan);
    EXPECT_EQ(res.vlan.vid, 250);
    EXPECT_EQ(res.vlan.tpid, router::ETHERTYPE_VLAN);
    EXPECT_EQ(res.l3_offset, 18);
}

TEST(EthernetTest, ParseQinQDoubleVlanFrame) {
    // Construct 802.1ad (0x88A8) outer + 802.1Q (0x8100) inner
    uint8_t buffer[64] = {0};
    router::mac_address_t dst(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    router::mac_address_t src(0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb);

    std::memcpy(buffer, dst.bytes, 6);
    std::memcpy(buffer + 6, src.bytes, 6);
    // Outer TPID = 0x88A8
    buffer[12] = 0x88; buffer[13] = 0xA8;
    // Outer TCI: PCP=3, VID=100 -> 0x6064
    buffer[14] = 0x60; buffer[15] = 0x64;
    // Inner TPID = 0x8100
    buffer[16] = 0x81; buffer[17] = 0x00;
    // Inner TCI: PCP=0, VID=200 -> 0x00C8
    buffer[18] = 0x00; buffer[19] = 0xC8;
    // Inner EtherType = IPv4 (0x0800)
    buffer[20] = 0x08; buffer[21] = 0x00;

    auto res = router::parse_ethernet_frame(buffer, sizeof(buffer));
    EXPECT_EQ(res.error, router::ethernet_error_t::SUCCESS);
    EXPECT_TRUE(res.has_vlan);
    EXPECT_EQ(res.vlan.tpid, router::ETHERTYPE_QINQ);
    EXPECT_EQ(res.vlan.vid, 100);
    EXPECT_EQ(res.vlan.pcp, 3);

    EXPECT_TRUE(res.has_inner_vlan);
    EXPECT_EQ(res.inner_vlan.tpid, router::ETHERTYPE_VLAN);
    EXPECT_EQ(res.inner_vlan.vid, 200);

    EXPECT_EQ(res.ethertype, router::ETHERTYPE_IPV4);
    EXPECT_EQ(res.l3_offset, 22);
}

TEST(EthernetTest, RewriteHeaderInPlace) {
    uint8_t buffer[64] = {0};
    router::mac_address_t old_dst(1, 2, 3, 4, 5, 6);
    router::mac_address_t old_src(7, 8, 9, 10, 11, 12);
    router::create_ethernet_header(buffer, sizeof(buffer), old_dst, old_src, router::ETHERTYPE_IPV4);

    router::mac_address_t new_dst(0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22);
    router::mac_address_t new_src(0xFE, 0xED, 0xFA, 0xCE, 0x33, 0x44);

    EXPECT_TRUE(router::rewrite_ethernet_header(buffer, sizeof(buffer), new_dst, new_src));

    auto res = router::parse_ethernet_frame(buffer, sizeof(buffer));
    EXPECT_EQ(res.dst_mac, new_dst);
    EXPECT_EQ(res.src_mac, new_src);
}

TEST(EthernetTest, TruncatedFrames) {
    uint8_t small_buf[10] = {0};
    auto res = router::parse_ethernet_frame(small_buf, sizeof(small_buf));
    EXPECT_EQ(res.error, router::ethernet_error_t::FRAME_TOO_SHORT);

    uint8_t vlan_buf[16] = {0};
    vlan_buf[12] = 0x81; vlan_buf[13] = 0x00; // VLAN tag indicated but truncated
    res = router::parse_ethernet_frame(vlan_buf, sizeof(vlan_buf));
    EXPECT_EQ(res.error, router::ethernet_error_t::TRUNCATED_VLAN_TAG);
}
