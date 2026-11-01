#include <gtest/gtest.h>
#include "router/lpm_trie.h"

TEST(LpmTrieTest, SingleRouteInsertAndLookup) {
    router::LpmTrie trie;
    router::route_entry_t r1;
    r1.prefix = router::ipv4_address_t(192, 168, 1, 0);
    r1.prefix_len = 24;
    r1.next_hop = router::ipv4_address_t(10, 0, 0, 1);
    r1.interface_id = 1;

    EXPECT_TRUE(trie.insert(r1));
    EXPECT_EQ(trie.size(), 1);

    router::route_entry_t matched;
    // Positive match in subnet
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(192, 168, 1, 55), &matched));
    EXPECT_EQ(matched.prefix, r1.prefix);
    EXPECT_EQ(matched.prefix_len, 24);
    EXPECT_EQ(matched.next_hop, r1.next_hop);
    EXPECT_EQ(matched.interface_id, 1);

    // Negative match outside subnet
    EXPECT_FALSE(trie.lookup(router::ipv4_address_t(192, 168, 2, 55), &matched));
}

TEST(LpmTrieTest, OverlappingPrefixesLongestMatch) {
    router::LpmTrie trie;

    // 0.0.0.0/0 (Default route)
    router::route_entry_t r_def;
    r_def.prefix = router::ipv4_address_t(0, 0, 0, 0);
    r_def.prefix_len = 0;
    r_def.interface_id = 10;
    trie.insert(r_def);

    // 10.0.0.0/8
    router::route_entry_t r_8;
    r_8.prefix = router::ipv4_address_t(10, 0, 0, 0);
    r_8.prefix_len = 8;
    r_8.interface_id = 11;
    trie.insert(r_8);

    // 10.1.0.0/16
    router::route_entry_t r_16;
    r_16.prefix = router::ipv4_address_t(10, 1, 0, 0);
    r_16.prefix_len = 16;
    r_16.interface_id = 12;
    trie.insert(r_16);

    // 10.1.2.0/24
    router::route_entry_t r_24;
    r_24.prefix = router::ipv4_address_t(10, 1, 2, 0);
    r_24.prefix_len = 24;
    r_24.interface_id = 13;
    trie.insert(r_24);

    // 10.1.2.100/32 (Host route)
    router::route_entry_t r_32;
    r_32.prefix = router::ipv4_address_t(10, 1, 2, 100);
    r_32.prefix_len = 32;
    r_32.interface_id = 14;
    trie.insert(r_32);

    EXPECT_EQ(trie.size(), 5);

    router::route_entry_t out;

    // 10.1.2.100 should match /32
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 1, 2, 100), &out));
    EXPECT_EQ(out.interface_id, 14);
    EXPECT_EQ(out.prefix_len, 32);

    // 10.1.2.101 should match /24
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 1, 2, 101), &out));
    EXPECT_EQ(out.interface_id, 13);
    EXPECT_EQ(out.prefix_len, 24);

    // 10.1.5.1 should match /16
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 1, 5, 1), &out));
    EXPECT_EQ(out.interface_id, 12);
    EXPECT_EQ(out.prefix_len, 16);

    // 10.2.1.1 should match /8
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 2, 1, 1), &out));
    EXPECT_EQ(out.interface_id, 11);
    EXPECT_EQ(out.prefix_len, 8);

    // 8.8.8.8 should match default route /0
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(8, 8, 8, 8), &out));
    EXPECT_EQ(out.interface_id, 10);
    EXPECT_EQ(out.prefix_len, 0);
}

TEST(LpmTrieTest, DeletionAndBranchPruning) {
    router::LpmTrie trie;

    router::route_entry_t r1{router::ipv4_address_t(10, 0, 0, 0), 8, router::ipv4_address_t(), 1, 0};
    router::route_entry_t r2{router::ipv4_address_t(10, 1, 2, 0), 24, router::ipv4_address_t(), 2, 0};
    router::route_entry_t r3{router::ipv4_address_t(10, 1, 2, 100), 32, router::ipv4_address_t(), 3, 0};

    trie.insert(r1);
    trie.insert(r2);
    trie.insert(r3);
    EXPECT_EQ(trie.size(), 3);
    size_t initial_nodes = trie.node_count();

    router::route_entry_t out;

    // Delete /32
    EXPECT_TRUE(trie.remove(router::ipv4_address_t(10, 1, 2, 100), 32));
    EXPECT_EQ(trie.size(), 2);
    EXPECT_LT(trie.node_count(), initial_nodes); // Pruning verified!

    // Looking up 10.1.2.100 now falls back to /24
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 1, 2, 100), &out));
    EXPECT_EQ(out.prefix_len, 24);
    EXPECT_EQ(out.interface_id, 2);

    // Delete /24
    EXPECT_TRUE(trie.remove(router::ipv4_address_t(10, 1, 2, 0), 24));
    EXPECT_EQ(trie.size(), 1);

    // Looking up 10.1.2.100 now falls back to /8
    EXPECT_TRUE(trie.lookup(router::ipv4_address_t(10, 1, 2, 100), &out));
    EXPECT_EQ(out.prefix_len, 8);
    EXPECT_EQ(out.interface_id, 1);

    // Delete /8
    EXPECT_TRUE(trie.remove(router::ipv4_address_t(10, 0, 0, 0), 8));
    EXPECT_EQ(trie.size(), 0);
    EXPECT_FALSE(trie.lookup(router::ipv4_address_t(10, 1, 2, 100), &out));
    EXPECT_EQ(trie.node_count(), 1); // Only root remaining
}

TEST(LpmTrieTest, MoveSemantics) {
    router::LpmTrie trie1;
    router::route_entry_t r1{router::ipv4_address_t(192, 168, 0, 0), 16, router::ipv4_address_t(), 5, 0};
    trie1.insert(r1);

    router::LpmTrie trie2(std::move(trie1));
    EXPECT_EQ(trie1.size(), 0);
    EXPECT_EQ(trie2.size(), 1);

    router::route_entry_t out;
    EXPECT_TRUE(trie2.lookup(router::ipv4_address_t(192, 168, 10, 1), &out));
    EXPECT_EQ(out.interface_id, 5);
}
