#ifndef ROUTER_ARP_H
#define ROUTER_ARP_H

#include "router/types.h"
#include <cstdint>
#include <cstddef>
#include <unordered_map>
#include <vector>
#include <deque>
#include <chrono>
#include <optional>

namespace router {

constexpr uint16_t ARP_HTYPE_ETHERNET = 0x0001;
constexpr uint16_t ARP_PTYPE_IPV4     = 0x0800;
constexpr uint8_t  ARP_HLEN_ETHERNET  = 6;
constexpr uint8_t  ARP_PLEN_IPV4      = 4;

constexpr uint16_t ARP_OP_REQUEST = 1;
constexpr uint16_t ARP_OP_REPLY   = 2;

#pragma pack(push, 1)

struct arp_header_t {
    uint16_t htype;      // Hardware type (1 = Ethernet)
    uint16_t ptype;      // Protocol type (0x0800 = IPv4)
    uint8_t  hlen;       // Hardware address length (6)
    uint8_t  plen;       // Protocol address length (4)
    uint16_t opcode;     // 1 = Request, 2 = Reply
    uint8_t  sender_mac[6];
    uint32_t sender_ip;  // Network byte order
    uint8_t  target_mac[6];
    uint32_t target_ip;  // Network byte order
};

#pragma pack(pop)

static_assert(sizeof(arp_header_t) == 28, "arp_header_t must be exactly 28 bytes");

enum class arp_error_t {
    SUCCESS = 0,
    PACKET_TOO_SHORT,
    UNSUPPORTED_HARDWARE_TYPE,
    UNSUPPORTED_PROTOCOL_TYPE,
    INVALID_ADDRESS_LENGTH,
    UNSUPPORTED_OPCODE,
    INVALID_ARGUMENT
};

struct arp_parse_result_t {
    arp_error_t error{arp_error_t::SUCCESS};
    uint16_t opcode{0};
    mac_address_t sender_mac;
    ipv4_address_t sender_ip;
    mac_address_t target_mac;
    ipv4_address_t target_ip;
};

enum class arp_entry_state_t {
    INCOMPLETE,
    REACHABLE,
    STALE,
    EXPIRED
};

struct arp_entry_t {
    ipv4_address_t ip;
    mac_address_t mac;
    arp_entry_state_t state{arp_entry_state_t::INCOMPLETE};
    std::chrono::steady_clock::time_point updated_at{};
    std::chrono::seconds ttl{300}; // Default 5 minutes
};

struct pending_arp_packet_t {
    packet_buffer_t packet;
    std::chrono::steady_clock::time_point queued_at;
};

class ArpCache {
public:
    static constexpr size_t DEFAULT_MAX_QUEUE_PER_IP = 16;
    static constexpr size_t DEFAULT_MAX_TOTAL_QUEUED = 1024;
    static constexpr std::chrono::seconds DEFAULT_ENTRY_TTL{300};
    static constexpr std::chrono::seconds DEFAULT_PENDING_TIMEOUT{5};

    ArpCache(std::chrono::seconds default_ttl = DEFAULT_ENTRY_TTL,
             size_t max_queue_per_ip = DEFAULT_MAX_QUEUE_PER_IP,
             size_t max_total_queued = DEFAULT_MAX_TOTAL_QUEUED);

    ~ArpCache() = default;

    /**
     * @brief Resolves next-hop MAC address from cache.
     * 
     * @param ip Destination / next-hop IP.
     * @param out_mac Pointer to write resolved MAC if found.
     * @return true if found and valid (REACHABLE), false otherwise.
     */
    bool resolve(ipv4_address_t ip, mac_address_t* out_mac) noexcept;

    /**
     * @brief Inserts or updates an ARP cache mapping (e.g. from received packet or ARP reply).
     */
    void update(ipv4_address_t ip, const mac_address_t& mac,
                arp_entry_state_t state = arp_entry_state_t::REACHABLE,
                std::chrono::seconds ttl = DEFAULT_ENTRY_TTL);

    /**
     * @brief Manually removes an IP from the cache.
     */
    bool remove(ipv4_address_t ip);

    /**
     * @brief Queues a packet waiting for ARP resolution of target IP.
     * 
     * @param target_ip The next-hop IP waiting for resolution.
     * @param packet The packet buffer to hold.
     * @return true if queued, false if queue limits exceeded.
     */
    bool queue_pending_packet(ipv4_address_t target_ip, const packet_buffer_t& packet);

    /**
     * @brief Dequeues all pending packets for target IP (called after ARP reply is processed).
     * 
     * @param target_ip The IP that was just resolved.
     * @return Vector of pending packets ready to be forwarded.
     */
    std::vector<packet_buffer_t> dequeue_pending_packets(ipv4_address_t target_ip);

    /**
     * @brief Sweeps expired entries and timed-out pending packets.
     * 
     * @param now Current time point.
     * @return Number of entries expired and pending packets dropped.
     */
    std::pair<size_t, size_t> sweep(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    /**
     * @brief Returns total number of cached ARP entries.
     */
    size_t size() const noexcept { return table_.size(); }

    /**
     * @brief Returns total number of pending packets currently queued.
     */
    size_t pending_packet_count() const noexcept { return total_queued_packets_; }

    /**
     * @brief Clears cache and pending queues.
     */
    void clear() noexcept;

private:
    std::chrono::seconds default_ttl_;
    size_t max_queue_per_ip_;
    size_t max_total_queued_;
    size_t total_queued_packets_{0};

    std::unordered_map<ipv4_address_t, arp_entry_t> table_;
    std::unordered_map<ipv4_address_t, std::deque<pending_arp_packet_t>> pending_packets_;
};

// ---------------------------------------------------------------------------
// ARP Packet Helpers
// ---------------------------------------------------------------------------

/**
 * @brief Parses an ARP payload (after L2 header).
 */
arp_parse_result_t parse_arp_packet(const uint8_t* payload, size_t length) noexcept;

/**
 * @brief Constructs a full Ethernet + ARP Request frame.
 * 
 * Destination MAC is broadcast (ff:ff:ff:ff:ff:ff).
 * 
 * @param buffer Output buffer.
 * @param buffer_size Capacity of buffer.
 * @param sender_mac Interface MAC address.
 * @param sender_ip Interface IP address.
 * @param target_ip Target IP being resolved.
 * @param vlan_id Optional VLAN ID (0 = untagged).
 * @return Total frame length created, or 0 on error.
 */
size_t create_arp_request_frame(uint8_t* buffer, size_t buffer_size,
                               const mac_address_t& sender_mac,
                               ipv4_address_t sender_ip,
                               ipv4_address_t target_ip,
                               uint16_t vlan_id = 0) noexcept;

/**
 * @brief Constructs a full Ethernet + ARP Reply frame in response to an ARP Request.
 * 
 * @param buffer Output buffer.
 * @param buffer_size Capacity of buffer.
 * @param sender_mac Router interface MAC.
 * @param sender_ip Router interface IP.
 * @param target_mac Requesting host's MAC.
 * @param target_ip Requesting host's IP.
 * @param vlan_id Optional VLAN ID (0 = untagged).
 * @return Total frame length created, or 0 on error.
 */
size_t create_arp_reply_frame(uint8_t* buffer, size_t buffer_size,
                             const mac_address_t& sender_mac,
                             ipv4_address_t sender_ip,
                             const mac_address_t& target_mac,
                             ipv4_address_t target_ip,
                             uint16_t vlan_id = 0) noexcept;

} // namespace router

#endif // ROUTER_ARP_H
