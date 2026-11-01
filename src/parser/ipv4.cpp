#include "router/ipv4.h"
#include "router/checksum.h"
#include <arpa/inet.h>
#include <cstring>

namespace router {

ipv4_parse_result_t parse_ipv4_packet(const uint8_t* packet, size_t length) noexcept {
    ipv4_parse_result_t res;

    if (packet == nullptr) {
        res.error = ipv4_error_t::INVALID_ARGUMENT;
        return res;
    }

    // Minimum IPv4 header is 20 bytes
    if (length < 20) {
        res.error = ipv4_error_t::HEADER_TOO_SHORT;
        return res;
    }

    uint8_t ver_ihl = packet[0];
    uint8_t version = (ver_ihl >> 4) & 0x0F;
    uint8_t ihl = ver_ihl & 0x0F;

    if (version != 4) {
        res.error = ipv4_error_t::INVALID_VERSION;
        return res;
    }

    if (ihl < 5) {
        res.error = ipv4_error_t::INVALID_IHL;
        return res;
    }

    uint8_t ihl_bytes = static_cast<uint8_t>(ihl * 4);
    if (length < ihl_bytes) {
        res.error = ipv4_error_t::HEADER_TOO_SHORT;
        return res;
    }

    uint16_t total_length_net = 0;
    std::memcpy(&total_length_net, packet + 2, sizeof(total_length_net));
    uint16_t total_length = ntohs(total_length_net);

    if (total_length < ihl_bytes) {
        res.error = ipv4_error_t::TOTAL_LENGTH_TOO_SHORT;
        return res;
    }

    if (length < total_length) {
        res.error = ipv4_error_t::PACKET_TRUNCATED;
        return res;
    }

    // Checksum verification over the header (ihl_bytes)
    if (!verify_checksum(packet, ihl_bytes)) {
        res.error = ipv4_error_t::CHECKSUM_ERROR;
        return res;
    }

    res.version = version;
    res.ihl_bytes = ihl_bytes;
    res.total_length = total_length;
    res.ttl = packet[8];
    res.protocol = packet[9];

    uint16_t cksum_net = 0;
    std::memcpy(&cksum_net, packet + 10, sizeof(cksum_net));
    res.checksum = ntohs(cksum_net);

    uint32_t src_ip_net = 0;
    std::memcpy(&src_ip_net, packet + 12, sizeof(src_ip_net));
    res.src_ip = ipv4_address_t::from_net_order(src_ip_net);

    uint32_t dst_ip_net = 0;
    std::memcpy(&dst_ip_net, packet + 16, sizeof(dst_ip_net));
    res.dst_ip = ipv4_address_t::from_net_order(dst_ip_net);

    // Flags & Fragment Offset
    uint16_t flags_fo_net = 0;
    std::memcpy(&flags_fo_net, packet + 6, sizeof(flags_fo_net));
    uint16_t flags_fo = ntohs(flags_fo_net);

    res.df = (flags_fo & 0x4000) != 0;
    res.mf = (flags_fo & 0x2000) != 0;
    res.fragment_offset = flags_fo & 0x1FFF;

    res.is_fragmented = res.mf || (res.fragment_offset > 0);
    res.is_first_fragment = res.is_fragmented && (res.fragment_offset == 0);

    res.payload_offset = ihl_bytes;
    res.payload_length = total_length - ihl_bytes;

    res.error = ipv4_error_t::SUCCESS;
    return res;
}

bool decrement_ipv4_ttl(uint8_t* packet, size_t length, uint8_t* new_ttl_out) noexcept {
    if (packet == nullptr || length < 20) {
        return false;
    }

    uint8_t ver_ihl = packet[0];
    uint8_t ihl = ver_ihl & 0x0F;
    if (ihl < 5 || length < static_cast<size_t>(ihl * 4)) {
        return false;
    }

    uint8_t current_ttl = packet[8];
    if (current_ttl <= 1) {
        return false; // TTL Expired
    }

    uint8_t next_ttl = static_cast<uint8_t>(current_ttl - 1);
    packet[8] = next_ttl;

    uint8_t protocol = packet[9];
    uint16_t old_checksum = 0;
    std::memcpy(&old_checksum, packet + 10, sizeof(old_checksum));

    // Fast incremental checksum update (RFC 1624)
    uint16_t new_checksum = checksum_update_ttl(old_checksum, current_ttl, next_ttl, protocol);
    std::memcpy(packet + 10, &new_checksum, sizeof(new_checksum));

    if (new_ttl_out != nullptr) {
        *new_ttl_out = next_ttl;
    }

    return true;
}

bool recalculate_ipv4_checksum(uint8_t* packet, size_t length) noexcept {
    if (packet == nullptr || length < 20) {
        return false;
    }

    uint8_t ver_ihl = packet[0];
    uint8_t ihl = ver_ihl & 0x0F;
    size_t header_len = static_cast<size_t>(ihl * 4);
    if (ihl < 5 || length < header_len) {
        return false;
    }

    // Set checksum to 0 before calculating
    packet[10] = 0;
    packet[11] = 0;

    uint16_t cksum = calculate_checksum(packet, header_len);
    std::memcpy(packet + 10, &cksum, sizeof(cksum));
    return true;
}

size_t create_ipv4_header(uint8_t* buffer, size_t buffer_size,
                         ipv4_address_t src,
                         ipv4_address_t dst,
                         uint8_t protocol,
                         uint16_t payload_len,
                         uint8_t ttl,
                         uint16_t id) noexcept {
    constexpr size_t min_ip_hdr = 20;
    if (buffer == nullptr || buffer_size < min_ip_hdr) {
        return 0;
    }

    // Standard 20-byte IPv4 header (version=4, ihl=5)
    buffer[0] = 0x45;
    buffer[1] = 0x00; // TOS/DSCP/ECN

    uint16_t total_length = static_cast<uint16_t>(min_ip_hdr + payload_len);
    uint16_t total_len_net = htons(total_length);
    std::memcpy(buffer + 2, &total_len_net, 2);

    uint16_t id_net = htons(id);
    std::memcpy(buffer + 4, &id_net, 2);

    uint16_t flags_fo = htons(0x4000); // DF flag set, offset=0
    std::memcpy(buffer + 6, &flags_fo, 2);

    buffer[8] = ttl;
    buffer[9] = protocol;

    // Zero checksum before computing
    buffer[10] = 0;
    buffer[11] = 0;

    uint32_t src_net = src.to_net_order();
    uint32_t dst_net = dst.to_net_order();
    std::memcpy(buffer + 12, &src_net, 4);
    std::memcpy(buffer + 16, &dst_net, 4);

    uint16_t cksum = calculate_checksum(buffer, min_ip_hdr);
    std::memcpy(buffer + 10, &cksum, 2);

    return min_ip_hdr;
}

} // namespace router
