#ifndef ROUTER_TYPES_H
#define ROUTER_TYPES_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <array>
#include <chrono>
#include <functional>

namespace router {

// Maximum Ethernet frame size supported (standard MTU 1500 + Ethernet + VLAN + margins)
constexpr size_t MAX_PACKET_SIZE = 2048;
constexpr size_t MIN_ETHERNET_FRAME_SIZE = 60; // Without 4-byte FCS
constexpr size_t MAX_ETHERNET_FRAME_SIZE = 1518;
constexpr size_t MAX_VLAN_FRAME_SIZE = 1522; // 1518 + 4 bytes 802.1Q
constexpr size_t MAX_JUMBO_FRAME_SIZE = 9022;

using interface_id_t = uint32_t;
constexpr interface_id_t INVALID_INTERFACE_ID = 0xFFFFFFFF;

// ---------------------------------------------------------------------------
// MAC Address
// ---------------------------------------------------------------------------
struct mac_address_t {
    uint8_t bytes[6];

    constexpr mac_address_t() : bytes{0, 0, 0, 0, 0, 0} {}
    constexpr mac_address_t(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5)
        : bytes{b0, b1, b2, b3, b4, b5} {}
    explicit mac_address_t(const uint8_t* raw_bytes) {
        if (raw_bytes != nullptr) {
            std::memcpy(bytes, raw_bytes, 6);
        } else {
            std::memset(bytes, 0, 6);
        }
    }

    bool is_broadcast() const noexcept {
        return bytes[0] == 0xFF && bytes[1] == 0xFF && bytes[2] == 0xFF &&
               bytes[3] == 0xFF && bytes[4] == 0xFF && bytes[5] == 0xFF;
    }

    bool is_multicast() const noexcept {
        return (bytes[0] & 0x01) != 0;
    }

    bool is_zero() const noexcept {
        return bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 &&
               bytes[3] == 0 && bytes[4] == 0 && bytes[5] == 0;
    }

    bool operator==(const mac_address_t& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 6) == 0;
    }

    bool operator!=(const mac_address_t& other) const noexcept {
        return !(*this == other);
    }

    bool operator<(const mac_address_t& other) const noexcept {
        return std::memcmp(bytes, other.bytes, 6) < 0;
    }

    std::string to_string() const;
    static mac_address_t from_string(const std::string& str);
    static mac_address_t broadcast() noexcept {
        return mac_address_t(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
    }
    static mac_address_t zero() noexcept {
        return mac_address_t(0, 0, 0, 0, 0, 0);
    }
};

// ---------------------------------------------------------------------------
// IPv4 Address (stored internally in host byte order for efficient arithmetic)
// ---------------------------------------------------------------------------
struct ipv4_address_t {
    uint32_t addr; // Host byte order

    constexpr ipv4_address_t() : addr(0) {}
    constexpr explicit ipv4_address_t(uint32_t host_addr) : addr(host_addr) {}
    constexpr ipv4_address_t(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        : addr((static_cast<uint32_t>(a) << 24) |
               (static_cast<uint32_t>(b) << 16) |
               (static_cast<uint32_t>(c) << 8)  |
                static_cast<uint32_t>(d)) {}

    static ipv4_address_t from_net_order(uint32_t net_addr) noexcept;
    uint32_t to_net_order() const noexcept;

    std::string to_string() const;
    static ipv4_address_t from_string(const std::string& str);

    bool is_zero() const noexcept { return addr == 0; }
    bool is_loopback() const noexcept { return (addr >> 24) == 127; }
    bool is_multicast() const noexcept { return (addr >> 28) == 14; } // 224.0.0.0/4
    bool is_broadcast() const noexcept { return addr == 0xFFFFFFFF; }

    bool operator==(const ipv4_address_t& other) const noexcept { return addr == other.addr; }
    bool operator!=(const ipv4_address_t& other) const noexcept { return addr != other.addr; }
    bool operator<(const ipv4_address_t& other) const noexcept { return addr < other.addr; }

    static ipv4_address_t any() noexcept { return ipv4_address_t(0); }
    static ipv4_address_t broadcast() noexcept { return ipv4_address_t(0xFFFFFFFF); }
};

// ---------------------------------------------------------------------------
// Network Interface Definition
// ---------------------------------------------------------------------------
struct network_interface_t {
    interface_id_t id{INVALID_INTERFACE_ID};
    std::string name;
    mac_address_t mac_addr;
    ipv4_address_t ip_addr;
    ipv4_address_t netmask;
    uint16_t mtu{1500};
    bool is_up{true};

    bool is_in_subnet(ipv4_address_t target_ip) const noexcept {
        return (target_ip.addr & netmask.addr) == (ip_addr.addr & netmask.addr);
    }
};

// ---------------------------------------------------------------------------
// Packet Buffer Descriptor (Zero-heap-allocation per packet)
// ---------------------------------------------------------------------------
struct alignas(64) packet_buffer_t {
    uint8_t data[MAX_PACKET_SIZE];
    size_t length{0};
    interface_id_t ingress_interface_id{INVALID_INTERFACE_ID};
    interface_id_t egress_interface_id{INVALID_INTERFACE_ID};
    std::chrono::steady_clock::time_point timestamp{};

    packet_buffer_t() = default;

    void reset() noexcept {
        length = 0;
        ingress_interface_id = INVALID_INTERFACE_ID;
        egress_interface_id = INVALID_INTERFACE_ID;
    }

    bool set_data(const uint8_t* src, size_t len) noexcept {
        if (len > MAX_PACKET_SIZE) {
            return false;
        }
        std::memcpy(data, src, len);
        length = len;
        return true;
    }
};

// ---------------------------------------------------------------------------
// Route Entry
// ---------------------------------------------------------------------------
struct route_entry_t {
    ipv4_address_t prefix;
    uint8_t prefix_len{0}; // 0 to 32
    ipv4_address_t next_hop;
    interface_id_t interface_id{INVALID_INTERFACE_ID};
    uint32_t metric{0};

    bool is_direct() const noexcept {
        return next_hop.is_zero();
    }

    bool is_default() const noexcept {
        return prefix.is_zero() && prefix_len == 0;
    }

    bool operator==(const route_entry_t& other) const noexcept {
        return prefix == other.prefix &&
               prefix_len == other.prefix_len &&
               next_hop == other.next_hop &&
               interface_id == other.interface_id &&
               metric == other.metric;
    }
};

// ---------------------------------------------------------------------------
// Router Statistics & Counters
// ---------------------------------------------------------------------------
struct alignas(64) router_stats_t {
    // RX / TX byte and packet counters
    uint64_t rx_packets{0};
    uint64_t rx_bytes{0};
    uint64_t tx_packets{0};
    uint64_t tx_bytes{0};

    // L2 counters
    uint64_t l2_broadcast_packets{0};
    uint64_t l2_multicast_packets{0};
    uint64_t l2_vlan_tagged_packets{0};
    uint64_t l2_frame_too_short{0};
    uint64_t l2_frame_too_long{0};
    uint64_t l2_dst_mac_mismatch{0};
    uint64_t l2_unsupported_ethertype{0};

    // L3 IPv4 counters
    uint64_t l3_ipv4_packets{0};
    uint64_t l3_checksum_errors{0};
    uint64_t l3_invalid_version{0};
    uint64_t l3_invalid_ihl{0};
    uint64_t l3_length_mismatch{0};
    uint64_t l3_ttl_expired{0};
    uint64_t l3_fragmented_dropped{0};
    uint64_t l3_no_route{0};
    uint64_t l3_forwarded{0};
    uint64_t l3_local_delivered{0};

    // ARP counters
    uint64_t arp_requests_received{0};
    uint64_t arp_replies_received{0};
    uint64_t arp_requests_sent{0};
    uint64_t arp_replies_sent{0};
    uint64_t arp_cache_hits{0};
    uint64_t arp_cache_misses{0};
    uint64_t arp_pending_queued{0};
    uint64_t arp_pending_dequeued{0};
    uint64_t arp_pending_dropped_full{0};
    uint64_t arp_pending_dropped_timeout{0};

    void reset() noexcept {
        std::memset(this, 0, sizeof(*this));
    }
};

} // namespace router

// Custom hash specialization for mac_address_t and ipv4_address_t
namespace std {
template <>
struct hash<router::mac_address_t> {
    size_t operator()(const router::mac_address_t& mac) const noexcept {
        size_t h = 0;
        for (int i = 0; i < 6; ++i) {
            h = (h * 31) + mac.bytes[i];
        }
        return h;
    }
};

template <>
struct hash<router::ipv4_address_t> {
    size_t operator()(const router::ipv4_address_t& ip) const noexcept {
        return std::hash<uint32_t>{}(ip.addr);
    }
};
} // namespace std

#endif // ROUTER_TYPES_H
