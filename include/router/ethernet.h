#ifndef ROUTER_ETHERNET_H
#define ROUTER_ETHERNET_H

#include "router/types.h"
#include <cstdint>
#include <cstddef>

namespace router {

// Standard EtherTypes (in host byte order)
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100; // 802.1Q
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8; // 802.1ad
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

#pragma pack(push, 1)

struct ethernet_header_t {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype; // Network byte order
};

struct vlan_tag_t {
    uint16_t tpid; // 0x8100 or 0x88A8 in network byte order
    uint16_t tci;  // PCP (3b), DEI (1b), VID (12b) in network byte order
};

#pragma pack(pop)

static_assert(sizeof(ethernet_header_t) == 14, "ethernet_header_t must be exactly 14 bytes");
static_assert(sizeof(vlan_tag_t) == 4, "vlan_tag_t must be exactly 4 bytes");

struct vlan_info_t {
    uint16_t vid{0};  // VLAN ID (0-4095)
    uint8_t pcp{0};   // Priority Code Point (0-7)
    bool dei{false};  // Drop Eligible Indicator
    uint16_t tpid{0}; // Tag Protocol Identifier (0x8100, 0x88A8)
};

enum class ethernet_error_t {
    SUCCESS = 0,
    FRAME_TOO_SHORT,
    FRAME_TOO_LONG,
    TRUNCATED_VLAN_TAG,
    UNSUPPORTED_ETHERTYPE,
    INVALID_ARGUMENT
};

struct ethernet_parse_result_t {
    ethernet_error_t error{ethernet_error_t::SUCCESS};
    mac_address_t dst_mac;
    mac_address_t src_mac;
    uint16_t ethertype{0}; // Inner EtherType (host byte order)
    size_t l3_offset{14};  // Byte offset to L3 payload
    size_t l3_length{0};   // Remaining payload length
    bool has_vlan{false};
    vlan_info_t vlan;
    bool has_inner_vlan{false};
    vlan_info_t inner_vlan; // For Q-in-Q (802.1ad)
};

/**
 * @brief Parses an Ethernet II frame, including optional 802.1Q / 802.1ad VLAN tags.
 * 
 * Validates frame bounds, extracts L2 addressing, unwraps VLAN tags to find
 * the inner EtherType, and returns the byte offset and length of the L3 payload.
 * 
 * @param frame Pointer to the raw frame bytes.
 * @param length Total length of the frame.
 * @return ethernet_parse_result_t Detailed parsing outcome.
 */
ethernet_parse_result_t parse_ethernet_frame(const uint8_t* frame, size_t length) noexcept;

/**
 * @brief Rewrites the L2 header in-place with new destination and source MAC addresses.
 * 
 * @param frame Pointer to the frame buffer.
 * @param length Length of the frame buffer.
 * @param new_dst_mac New destination MAC address (typically next-hop router/host).
 * @param new_src_mac New source MAC address (typically egress interface MAC).
 * @return true if rewrite succeeded, false if buffer too small.
 */
bool rewrite_ethernet_header(uint8_t* frame, size_t length,
                            const mac_address_t& new_dst_mac,
                            const mac_address_t& new_src_mac) noexcept;

/**
 * @brief Formats an Ethernet II header with optional 802.1Q VLAN tag.
 * 
 * @param buffer Output buffer.
 * @param buffer_size Capacity of output buffer.
 * @param dst Destination MAC.
 * @param src Source MAC.
 * @param ethertype Inner EtherType (host byte order).
 * @param vlan_id Optional VLAN ID (0 = untagged).
 * @return Number of header bytes written (14 or 18), or 0 on error.
 */
size_t create_ethernet_header(uint8_t* buffer, size_t buffer_size,
                             const mac_address_t& dst,
                             const mac_address_t& src,
                             uint16_t ethertype,
                             uint16_t vlan_id = 0) noexcept;

} // namespace router

#endif // ROUTER_ETHERNET_H
