#ifndef ROUTER_IPV4_H
#define ROUTER_IPV4_H

#include "router/types.h"
#include <cstdint>
#include <cstddef>

namespace router {

// Standard IP Protocols
constexpr uint8_t IPPROTO_ICMP_V = 1;
constexpr uint8_t IPPROTO_TCP_V  = 6;
constexpr uint8_t IPPROTO_UDP_V  = 17;

#pragma pack(push, 1)

struct ipv4_header_t {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

#pragma pack(pop)

static_assert(sizeof(ipv4_header_t) == 20, "ipv4_header_t must be exactly 20 bytes");

enum class ipv4_error_t {
    SUCCESS = 0,
    HEADER_TOO_SHORT,
    INVALID_VERSION,
    INVALID_IHL,
    TOTAL_LENGTH_TOO_SHORT,
    PACKET_TRUNCATED,
    CHECKSUM_ERROR,
    TTL_EXPIRED,
    INVALID_ARGUMENT
};

struct ipv4_parse_result_t {
    ipv4_error_t error{ipv4_error_t::SUCCESS};
    uint8_t version{0};
    uint8_t ihl_bytes{0};
    uint16_t total_length{0};
    uint8_t ttl{0};
    uint8_t protocol{0};
    uint16_t checksum{0};
    ipv4_address_t src_ip;
    ipv4_address_t dst_ip;

    // Fragmentation fields
    bool df{false};              // Don't Fragment
    bool mf{false};              // More Fragments
    uint16_t fragment_offset{0}; // In 8-byte units (multiply by 8 for bytes)
    bool is_fragmented{false};
    bool is_first_fragment{false};

    size_t payload_offset{0};
    size_t payload_length{0};
};

/**
 * @brief Parses and validates an IPv4 packet header.
 * 
 * Verifies version, IHL, packet boundaries, and RFC 1071 header checksum.
 * Extracts addressing, protocol, TTL, and fragmentation state.
 * 
 * @param packet Pointer to start of IPv4 packet.
 * @param length Available length in buffer from start of IPv4 packet.
 * @return ipv4_parse_result_t Detailed parsing outcome.
 */
ipv4_parse_result_t parse_ipv4_packet(const uint8_t* packet, size_t length) noexcept;

/**
 * @brief Decrements TTL and updates the IPv4 header checksum incrementally.
 * 
 * If TTL <= 1, returns false (TTL expired).
 * Otherwise decrements TTL and updates checksum using RFC 1624 algorithm.
 * 
 * @param packet Pointer to start of IPv4 packet.
 * @param length Available length of buffer.
 * @param new_ttl Pointer to receive the decremented TTL (optional).
 * @return true if TTL successfully decremented, false if TTL was <= 1 or packet invalid.
 */
bool decrement_ipv4_ttl(uint8_t* packet, size_t length, uint8_t* new_ttl = nullptr) noexcept;

/**
 * @brief Fully recalculates the IPv4 header checksum and writes it to the header.
 * 
 * Sets the checksum field to 0, computes RFC 1071 sum over (IHL * 4) bytes,
 * and writes the result.
 * 
 * @param packet Pointer to start of IPv4 packet.
 * @param length Available length of buffer.
 * @return true on success, false if buffer too small or IHL invalid.
 */
bool recalculate_ipv4_checksum(uint8_t* packet, size_t length) noexcept;

/**
 * @brief Helper to craft a valid IPv4 header into a buffer.
 * 
 * @param buffer Output buffer.
 * @param buffer_size Capacity of buffer.
 * @param src Source IP.
 * @param dst Destination IP.
 * @param protocol L4 protocol (e.g. 1, 6, 17).
 * @param payload_len Length of L4 payload.
 * @param ttl Time to live (default 64).
 * @param id Identification field (default 0).
 * @return Number of header bytes written (20), or 0 on error.
 */
size_t create_ipv4_header(uint8_t* buffer, size_t buffer_size,
                         ipv4_address_t src,
                         ipv4_address_t dst,
                         uint8_t protocol,
                         uint16_t payload_len,
                         uint8_t ttl = 64,
                         uint16_t id = 0) noexcept;

} // namespace router

#endif // ROUTER_IPV4_H
