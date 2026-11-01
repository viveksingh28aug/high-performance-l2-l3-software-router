#include "router/lpm_trie.h"
#include "router/routing_table.h"
#include "router/packet_forwarder.h"
#include "router/ethernet.h"
#include "router/ipv4.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>

struct BenchmarkResult {
    std::string test_name;
    size_t table_size;
    size_t lookup_count;
    double elapsed_ms;
    double mpps;
    double ns_per_lookup;
};

void print_result(const BenchmarkResult& r) {
    std::cout << "| " << std::left << std::setw(30) << r.test_name
              << " | " << std::right << std::setw(10) << r.table_size
              << " | " << std::right << std::setw(12) << r.lookup_count
              << " | " << std::right << std::setw(12) << std::fixed << std::setprecision(2) << r.elapsed_ms
              << " | " << std::right << std::setw(10) << std::fixed << std::setprecision(2) << r.mpps
              << " | " << std::right << std::setw(10) << std::fixed << std::setprecision(1) << r.ns_per_lookup
              << " |\n";
}

// Generate realistic or uniform route entries
std::vector<router::route_entry_t> generate_routes(size_t count, int fixed_prefix_len = -1) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> ip_dist(1, 0xE0000000); // 0.0.0.1 to 223.255.255.255 (Unicast)
    std::uniform_int_distribution<int> weight_dist(1, 100);

    std::vector<router::route_entry_t> routes;
    routes.reserve(count);

    for (size_t i = 0; i < count; ++i) {
        router::route_entry_t r;
        r.prefix = router::ipv4_address_t(ip_dist(rng));

        if (fixed_prefix_len >= 0 && fixed_prefix_len <= 32) {
            r.prefix_len = static_cast<uint8_t>(fixed_prefix_len);
        } else {
            // Realistic Internet FIB Distribution:
            // ~5% /8, ~15% /16, ~65% /24, ~15% /32
            int w = weight_dist(rng);
            if (w <= 5) r.prefix_len = 8;
            else if (w <= 20) r.prefix_len = 16;
            else if (w <= 85) r.prefix_len = 24;
            else r.prefix_len = 32;
        }

        r.next_hop = router::ipv4_address_t(10, 0, 0, static_cast<uint8_t>((i % 250) + 1));
        r.interface_id = static_cast<router::interface_id_t>((i % 4) + 1);
        r.metric = static_cast<uint32_t>(i % 100);
        routes.push_back(r);
    }
    return routes;
}

std::vector<router::ipv4_address_t> generate_query_ips(size_t count) {
    std::mt19937 rng(999);
    std::uniform_int_distribution<uint32_t> ip_dist(1, 0xE0000000);

    std::vector<router::ipv4_address_t> ips;
    ips.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        ips.push_back(router::ipv4_address_t(ip_dist(rng)));
    }
    return ips;
}

BenchmarkResult run_lpm_benchmark(const std::string& name, size_t table_size,
                                  size_t lookup_count, int fixed_prefix_len = -1) {
    router::LpmTrie trie;
    auto routes = generate_routes(table_size, fixed_prefix_len);
    for (const auto& r : routes) {
        trie.insert(r);
    }

    auto queries = generate_query_ips(lookup_count);

    router::route_entry_t out;
    size_t hits = 0;

    // Warm-up
    for (size_t i = 0; i < std::min<size_t>(lookup_count, 10000); ++i) {
        if (trie.lookup(queries[i], &out)) {
            ++hits;
        }
    }

    // Timed Monotonic Benchmark
    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < lookup_count; ++i) {
        if (trie.lookup(queries[i], &out)) {
            ++hits;
        }
    }
    auto end = std::chrono::steady_clock::now();

    // Prevent compiler from optimizing away lookups
    volatile size_t prevent_opt = hits;
    (void)prevent_opt;

    std::chrono::duration<double, std::milli> duration = end - start;
    double elapsed_ms = duration.count();
    double seconds = elapsed_ms / 1000.0;
    double mpps = (static_cast<double>(lookup_count) / seconds) / 1000000.0;
    double ns_per_lookup = (elapsed_ms * 1000000.0) / static_cast<double>(lookup_count);

    return BenchmarkResult{name, table_size, lookup_count, elapsed_ms, mpps, ns_per_lookup};
}

BenchmarkResult run_pipeline_benchmark(const std::string& name, size_t packet_count) {
    router::PacketForwarder router;

    router::network_interface_t iface1;
    iface1.id = 1;
    iface1.name = "eth0";
    iface1.mac_addr = router::mac_address_t(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    iface1.ip_addr = router::ipv4_address_t(192, 168, 1, 1);
    iface1.netmask = router::ipv4_address_t(255, 255, 255, 0);
    router.add_interface(iface1);

    router::network_interface_t iface2;
    iface2.id = 2;
    iface2.name = "eth1";
    iface2.mac_addr = router::mac_address_t(0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE);
    iface2.ip_addr = router::ipv4_address_t(10, 0, 0, 1);
    iface2.netmask = router::ipv4_address_t(255, 255, 255, 0);
    router.add_interface(iface2);

    // Add route for 172.16.0.0/16 via 10.0.0.2
    router.routing_table().add_route(router::ipv4_address_t(172, 16, 0, 0), 16,
                                     router::ipv4_address_t(10, 0, 0, 2), iface2.id, 10);
    // Add ARP entry for 10.0.0.2
    router.arp_cache().update(router::ipv4_address_t(10, 0, 0, 2),
                              router::mac_address_t(0x52, 0x54, 0x00, 0x11, 0x22, 0x33));

    // Pre-craft prototype packet
    router::packet_buffer_t base_pkt;
    base_pkt.ingress_interface_id = iface1.id;
    size_t l2_len = router::create_ethernet_header(
        base_pkt.data, router::MAX_PACKET_SIZE, iface1.mac_addr,
        router::mac_address_t(0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33), router::ETHERTYPE_IPV4);
    size_t l3_len = router::create_ipv4_header(
        base_pkt.data + l2_len, router::MAX_PACKET_SIZE - l2_len,
        router::ipv4_address_t(192, 168, 1, 100), router::ipv4_address_t(172, 16, 5, 20),
        router::IPPROTO_UDP_V, 20, 64);
    base_pkt.length = l2_len + l3_len + 20;

    std::vector<router::packet_buffer_t> tx_pkts;
    tx_pkts.reserve(4);

    // Warm-up
    for (size_t i = 0; i < 10000; ++i) {
        router::packet_buffer_t pkt = base_pkt;
        tx_pkts.clear();
        router.process_packet(pkt, tx_pkts);
    }

    auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < packet_count; ++i) {
        router::packet_buffer_t pkt = base_pkt;
        tx_pkts.clear();
        router.process_packet(pkt, tx_pkts);
    }
    auto end = std::chrono::steady_clock::now();

    std::chrono::duration<double, std::milli> duration = end - start;
    double elapsed_ms = duration.count();
    double seconds = elapsed_ms / 1000.0;
    double mpps = (static_cast<double>(packet_count) / seconds) / 1000000.0;
    double ns_per_lookup = (elapsed_ms * 1000000.0) / static_cast<double>(packet_count);

    return BenchmarkResult{name, 1, packet_count, elapsed_ms, mpps, ns_per_lookup};
}

int main() {
    std::cout << "========================================================================================\n";
    std::cout << "               L2/L3 SOFTWARE ROUTER PERFORMANCE BENCHMARKS (ACTUAL RUN)                \n";
    std::cout << "========================================================================================\n";
    std::cout << "| " << std::left << std::setw(30) << "Benchmark Scenario"
              << " | " << std::right << std::setw(10) << "Routes"
              << " | " << std::right << std::setw(12) << "Lookups"
              << " | " << std::right << std::setw(12) << "Time (ms)"
              << " | " << std::right << std::setw(10) << "Mpps"
              << " | " << std::right << std::setw(10) << "ns/lookup"
              << " |\n";
    std::cout << "|--------------------------------+------------+--------------+--------------+------------+------------|\n";

    std::vector<BenchmarkResult> results;

    // 100,000 lookups with realistic FIB
    results.push_back(run_lpm_benchmark("100k Lookups (100 routes)", 100, 100000));
    results.push_back(run_lpm_benchmark("100k Lookups (1k routes)", 1000, 100000));
    results.push_back(run_lpm_benchmark("100k Lookups (10k routes)", 10000, 100000));
    results.push_back(run_lpm_benchmark("100k Lookups (50k routes)", 50000, 100000));

    // 1,000,000 lookups with realistic FIB
    results.push_back(run_lpm_benchmark("1M Lookups (100 routes)", 100, 1000000));
    results.push_back(run_lpm_benchmark("1M Lookups (1k routes)", 1000, 1000000));
    results.push_back(run_lpm_benchmark("1M Lookups (10k routes)", 10000, 1000000));
    results.push_back(run_lpm_benchmark("1M Lookups (50k routes)", 50000, 1000000));

    // Different Prefix Lengths (10,000 routes each, 1M lookups)
    results.push_back(run_lpm_benchmark("1M Lookups (/8 routes)", 10000, 1000000, 8));
    results.push_back(run_lpm_benchmark("1M Lookups (/16 routes)", 10000, 1000000, 16));
    results.push_back(run_lpm_benchmark("1M Lookups (/24 routes)", 10000, 1000000, 24));
    results.push_back(run_lpm_benchmark("1M Lookups (/32 routes)", 10000, 1000000, 32));

    // End-to-End Packet Processing Pipeline Fast-Path
    results.push_back(run_pipeline_benchmark("Full Pipeline Fast-Path", 100000));
    results.push_back(run_pipeline_benchmark("Full Pipeline Fast-Path", 1000000));

    for (const auto& r : results) {
        print_result(r);
    }
    std::cout << "========================================================================================\n";

    return 0;
}
