#include <gtest/gtest.h>
#include "router/routing_table.h"

TEST(RoutingTableTest, MaskConversion) {
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(255, 255, 255, 0)), 24);
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(255, 255, 0, 0)), 16);
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(255, 0, 0, 0)), 8);
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(255, 255, 255, 255)), 32);
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(0, 0, 0, 0)), 0);

    // Non-contiguous invalid netmask should return 0
    EXPECT_EQ(router::RoutingTable::mask_to_prefix_len(router::ipv4_address_t(255, 0, 255, 0)), 0);

    // Prefix to mask
    EXPECT_EQ(router::RoutingTable::prefix_len_to_mask(24), router::ipv4_address_t(255, 255, 255, 0));
    EXPECT_EQ(router::RoutingTable::prefix_len_to_mask(16), router::ipv4_address_t(255, 255, 0, 0));
    EXPECT_EQ(router::RoutingTable::prefix_len_to_mask(0), router::ipv4_address_t(0, 0, 0, 0));
    EXPECT_EQ(router::RoutingTable::prefix_len_to_mask(32), router::ipv4_address_t(255, 255, 255, 255));
}

TEST(RoutingTableTest, AddRouteCidrAndDefault) {
    router::RoutingTable rt;

    EXPECT_TRUE(rt.add_route_cidr("192.168.10.0/24", router::ipv4_address_t(192, 168, 1, 1), 1, 10));
    EXPECT_TRUE(rt.set_default_route(router::ipv4_address_t(10, 0, 0, 1), 2, 20));
    EXPECT_EQ(rt.size(), 2);

    auto res1 = rt.lookup(router::ipv4_address_t(192, 168, 10, 50));
    ASSERT_TRUE(res1.has_value());
    EXPECT_EQ(res1->interface_id, 1);
    EXPECT_EQ(res1->metric, 10);

    auto res2 = rt.lookup(router::ipv4_address_t(8, 8, 8, 8));
    ASSERT_TRUE(res2.has_value());
    EXPECT_EQ(res2->interface_id, 2);
    EXPECT_EQ(res2->metric, 20);

    // Delete default route
    EXPECT_TRUE(rt.delete_default_route());
    EXPECT_EQ(rt.size(), 1);
    EXPECT_FALSE(rt.lookup(router::ipv4_address_t(8, 8, 8, 8)).has_value());
}

TEST(RoutingTableTest, GetAllRoutesAndClear) {
    router::RoutingTable rt;
    rt.add_route_cidr("10.0.0.0/8", router::ipv4_address_t(1, 1, 1, 1), 1);
    rt.add_route_cidr("20.0.0.0/8", router::ipv4_address_t(2, 2, 2, 2), 2);
    rt.add_route_cidr("30.0.0.0/8", router::ipv4_address_t(3, 3, 3, 3), 3);

    auto routes = rt.get_all_routes();
    EXPECT_EQ(routes.size(), 3);

    rt.clear();
    EXPECT_EQ(rt.size(), 0);
    EXPECT_EQ(rt.get_all_routes().size(), 0);
}
