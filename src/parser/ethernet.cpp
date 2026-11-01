#include "router/ethernet.h"
#include <arpa/inet.h>
#include <cstring>

namespace router {

ethernet_parse_result_t parse_ethernet_frame(const uint8_t* frame, size_t length) noexcept {
    ethernet_parse_result_t res;

    if (frame == nullptr) {
        res.error = ethernet_error_t::INVALID_ARGUMENT;
        return res;
    }

    if (length < sizeof(ethernet_header_t)) {
        res.error = ethernet_error_t::FRAME_TOO_SHORT;
        return res;
    }

    if (length > MAX_JUMBO_FRAME_SIZE) {
        res.error = ethernet_error_t::FRAME_TOO_LONG;
        return res;
    }

    const auto* hdr = reinterpret_cast<const ethernet_header_t*>(frame);
    res.dst_mac = mac_address_t(hdr->dst_mac);
    res.src_mac = mac_address_t(hdr->src_mac);

    uint16_t ethertype = ntohs(hdr->ethertype);
    size_t current_offset = sizeof(ethernet_header_t);

    // Check for Outer VLAN (802.1Q or 802.1ad Service VLAN)
    if (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) {
        if (length < current_offset + sizeof(vlan_tag_t)) {
            res.error = ethernet_error_t::TRUNCATED_VLAN_TAG;
            return res;
        }

        uint16_t tci_net = 0;
        std::memcpy(&tci_net, frame + current_offset, sizeof(tci_net));
        uint16_t tci = ntohs(tci_net);

        res.has_vlan = true;
        res.vlan.tpid = ethertype;
        res.vlan.vid = tci & 0x0FFF;
        res.vlan.pcp = static_cast<uint8_t>((tci >> 13) & 0x07);
        res.vlan.dei = ((tci >> 12) & 0x01) != 0;

        current_offset += sizeof(tci_net); // 2 bytes for TCI

        // Next 2 bytes is the next EtherType
        if (length < current_offset + 2) {
            res.error = ethernet_error_t::TRUNCATED_VLAN_TAG;
            return res;
        }

        uint16_t next_ethertype_net = 0;
        std::memcpy(&next_ethertype_net, frame + current_offset, sizeof(next_ethertype_net));
        ethertype = ntohs(next_ethertype_net);
        current_offset += 2;

        // Check for Inner VLAN (Q-in-Q second tag)
        if (ethertype == ETHERTYPE_VLAN) {
            if (length < current_offset + 2) {
                res.error = ethernet_error_t::TRUNCATED_VLAN_TAG;
                return res;
            }

            uint16_t inner_tci_net = 0;
            std::memcpy(&inner_tci_net, frame + current_offset, sizeof(inner_tci_net));
            uint16_t inner_tci = ntohs(inner_tci_net);

            res.has_inner_vlan = true;
            res.inner_vlan.tpid = ethertype;
            res.inner_vlan.vid = inner_tci & 0x0FFF;
            res.inner_vlan.pcp = static_cast<uint8_t>((inner_tci >> 13) & 0x07);
            res.inner_vlan.dei = ((inner_tci >> 12) & 0x01) != 0;

            current_offset += sizeof(inner_tci_net);

            // Inner payload EtherType
            if (length < current_offset + 2) {
                res.error = ethernet_error_t::TRUNCATED_VLAN_TAG;
                return res;
            }

            uint16_t inner_type_net = 0;
            std::memcpy(&inner_type_net, frame + current_offset, sizeof(inner_type_net));
            ethertype = ntohs(inner_type_net);
            current_offset += 2;
        }
    }

    res.ethertype = ethertype;
    res.l3_offset = current_offset;
    res.l3_length = length - current_offset;
    res.error = ethernet_error_t::SUCCESS;
    return res;
}

bool rewrite_ethernet_header(uint8_t* frame, size_t length,
                            const mac_address_t& new_dst_mac,
                            const mac_address_t& new_src_mac) noexcept {
    if (frame == nullptr || length < sizeof(ethernet_header_t)) {
        return false;
    }
    auto* hdr = reinterpret_cast<ethernet_header_t*>(frame);
    std::memcpy(hdr->dst_mac, new_dst_mac.bytes, 6);
    std::memcpy(hdr->src_mac, new_src_mac.bytes, 6);
    return true;
}

size_t create_ethernet_header(uint8_t* buffer, size_t buffer_size,
                             const mac_address_t& dst,
                             const mac_address_t& src,
                             uint16_t ethertype,
                             uint16_t vlan_id) noexcept {
    if (buffer == nullptr) {
        return 0;
    }

    if (vlan_id == 0) {
        // Standard untagged Ethernet II frame (14 bytes)
        if (buffer_size < sizeof(ethernet_header_t)) {
            return 0;
        }
        auto* hdr = reinterpret_cast<ethernet_header_t*>(buffer);
        std::memcpy(hdr->dst_mac, dst.bytes, 6);
        std::memcpy(hdr->src_mac, src.bytes, 6);
        hdr->ethertype = htons(ethertype);
        return sizeof(ethernet_header_t);
    } else {
        // 802.1Q tagged frame (18 bytes)
        constexpr size_t tagged_hdr_size = sizeof(ethernet_header_t) + 4;
        if (buffer_size < tagged_hdr_size) {
            return 0;
        }
        auto* hdr = reinterpret_cast<ethernet_header_t*>(buffer);
        std::memcpy(hdr->dst_mac, dst.bytes, 6);
        std::memcpy(hdr->src_mac, src.bytes, 6);
        hdr->ethertype = htons(ETHERTYPE_VLAN);

        uint16_t tci = htons(static_cast<uint16_t>(vlan_id & 0x0FFF));
        uint16_t inner_type = htons(ethertype);
        std::memcpy(buffer + 14, &tci, 2);
        std::memcpy(buffer + 16, &inner_type, 2);
        return tagged_hdr_size;
    }
}

} // namespace router
