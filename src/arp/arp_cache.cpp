#include "router/arp.h"
#include "router/ethernet.h"
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

namespace router {

ArpCache::ArpCache(std::chrono::seconds default_ttl,
                   size_t max_queue_per_ip,
                   size_t max_total_queued)
    : default_ttl_(default_ttl),
      max_queue_per_ip_(max_queue_per_ip),
      max_total_queued_(max_total_queued) {}

bool ArpCache::resolve(ipv4_address_t ip, mac_address_t* out_mac) noexcept {
    auto it = table_.find(ip);
    if (it == table_.end()) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    if (now - it->second.updated_at > it->second.ttl) {
        it->second.state = arp_entry_state_t::EXPIRED;
        return false;
    }

    if (it->second.state != arp_entry_state_t::REACHABLE) {
        return false;
    }

    if (out_mac != nullptr) {
        *out_mac = it->second.mac;
    }
    return true;
}

void ArpCache::update(ipv4_address_t ip, const mac_address_t& mac,
                      arp_entry_state_t state,
                      std::chrono::seconds ttl) {
    arp_entry_t entry;
    entry.ip = ip;
    entry.mac = mac;
    entry.state = state;
    entry.updated_at = std::chrono::steady_clock::now();
    entry.ttl = ttl;
    table_[ip] = entry;
}

bool ArpCache::remove(ipv4_address_t ip) {
    return table_.erase(ip) > 0;
}

bool ArpCache::queue_pending_packet(ipv4_address_t target_ip, const packet_buffer_t& packet) {
    if (total_queued_packets_ >= max_total_queued_) {
        return false;
    }

    auto& q = pending_packets_[target_ip];
    if (q.size() >= max_queue_per_ip_) {
        // Drop the oldest packet in this queue
        q.pop_front();
        --total_queued_packets_;
    }

    pending_arp_packet_t pending_item;
    pending_item.packet = packet;
    pending_item.queued_at = std::chrono::steady_clock::now();

    q.push_back(pending_item);
    ++total_queued_packets_;
    return true;
}

std::vector<packet_buffer_t> ArpCache::dequeue_pending_packets(ipv4_address_t target_ip) {
    std::vector<packet_buffer_t> packets;
    auto it = pending_packets_.find(target_ip);
    if (it == pending_packets_.end()) {
        return packets;
    }

    packets.reserve(it->second.size());
    for (auto& item : it->second) {
        packets.push_back(std::move(item.packet));
        --total_queued_packets_;
    }
    pending_packets_.erase(it);
    return packets;
}

std::pair<size_t, size_t> ArpCache::sweep(std::chrono::steady_clock::time_point now) {
    size_t entries_expired = 0;
    size_t packets_dropped = 0;

    // Sweep expired ARP entries
    for (auto it = table_.begin(); it != table_.end(); ) {
        if (now - it->second.updated_at > it->second.ttl) {
            it = table_.erase(it);
            ++entries_expired;
        } else {
            ++it;
        }
    }

    // Sweep timed-out pending packets
    for (auto it = pending_packets_.begin(); it != pending_packets_.end(); ) {
        auto& q = it->second;
        while (!q.empty() && (now - q.front().queued_at > DEFAULT_PENDING_TIMEOUT)) {
            q.pop_front();
            --total_queued_packets_;
            ++packets_dropped;
        }
        if (q.empty()) {
            it = pending_packets_.erase(it);
        } else {
            ++it;
        }
    }

    return {entries_expired, packets_dropped};
}

void ArpCache::clear() noexcept {
    table_.clear();
    pending_packets_.clear();
    total_queued_packets_ = 0;
}

arp_parse_result_t parse_arp_packet(const uint8_t* payload, size_t length) noexcept {
    arp_parse_result_t res;

    if (payload == nullptr) {
        res.error = arp_error_t::INVALID_ARGUMENT;
        return res;
    }

    if (length < sizeof(arp_header_t)) {
        res.error = arp_error_t::PACKET_TOO_SHORT;
        return res;
    }

    const auto* hdr = reinterpret_cast<const arp_header_t*>(payload);

    uint16_t htype = ntohs(hdr->htype);
    uint16_t ptype = ntohs(hdr->ptype);
    if (htype != ARP_HTYPE_ETHERNET) {
        res.error = arp_error_t::UNSUPPORTED_HARDWARE_TYPE;
        return res;
    }
    if (ptype != ARP_PTYPE_IPV4) {
        res.error = arp_error_t::UNSUPPORTED_PROTOCOL_TYPE;
        return res;
    }
    if (hdr->hlen != ARP_HLEN_ETHERNET || hdr->plen != ARP_PLEN_IPV4) {
        res.error = arp_error_t::INVALID_ADDRESS_LENGTH;
        return res;
    }

    uint16_t opcode = ntohs(hdr->opcode);
    if (opcode != ARP_OP_REQUEST && opcode != ARP_OP_REPLY) {
        res.error = arp_error_t::UNSUPPORTED_OPCODE;
        return res;
    }

    res.opcode = opcode;
    res.sender_mac = mac_address_t(hdr->sender_mac);
    res.sender_ip = ipv4_address_t::from_net_order(hdr->sender_ip);
    res.target_mac = mac_address_t(hdr->target_mac);
    res.target_ip = ipv4_address_t::from_net_order(hdr->target_ip);
    res.error = arp_error_t::SUCCESS;

    return res;
}

size_t create_arp_request_frame(uint8_t* buffer, size_t buffer_size,
                               const mac_address_t& sender_mac,
                               ipv4_address_t sender_ip,
                               ipv4_address_t target_ip,
                               uint16_t vlan_id) noexcept {
    if (buffer == nullptr) {
        return 0;
    }

    size_t l2_hdr_len = create_ethernet_header(
        buffer, buffer_size, mac_address_t::broadcast(), sender_mac, ETHERTYPE_ARP, vlan_id);
    if (l2_hdr_len == 0 || buffer_size < l2_hdr_len + sizeof(arp_header_t)) {
        return 0;
    }

    auto* arp = reinterpret_cast<arp_header_t*>(buffer + l2_hdr_len);
    arp->htype = htons(ARP_HTYPE_ETHERNET);
    arp->ptype = htons(ARP_PTYPE_IPV4);
    arp->hlen = ARP_HLEN_ETHERNET;
    arp->plen = ARP_PLEN_IPV4;
    arp->opcode = htons(ARP_OP_REQUEST);

    std::memcpy(arp->sender_mac, sender_mac.bytes, 6);
    arp->sender_ip = sender_ip.to_net_order();
    std::memset(arp->target_mac, 0, 6);
    arp->target_ip = target_ip.to_net_order();

    size_t total_len = l2_hdr_len + sizeof(arp_header_t);
    // Pad to minimum Ethernet frame size (60 bytes)
    if (total_len < MIN_ETHERNET_FRAME_SIZE && buffer_size >= MIN_ETHERNET_FRAME_SIZE) {
        std::memset(buffer + total_len, 0, MIN_ETHERNET_FRAME_SIZE - total_len);
        total_len = MIN_ETHERNET_FRAME_SIZE;
    }

    return total_len;
}

size_t create_arp_reply_frame(uint8_t* buffer, size_t buffer_size,
                             const mac_address_t& sender_mac,
                             ipv4_address_t sender_ip,
                             const mac_address_t& target_mac,
                             ipv4_address_t target_ip,
                             uint16_t vlan_id) noexcept {
    if (buffer == nullptr) {
        return 0;
    }

    size_t l2_hdr_len = create_ethernet_header(
        buffer, buffer_size, target_mac, sender_mac, ETHERTYPE_ARP, vlan_id);
    if (l2_hdr_len == 0 || buffer_size < l2_hdr_len + sizeof(arp_header_t)) {
        return 0;
    }

    auto* arp = reinterpret_cast<arp_header_t*>(buffer + l2_hdr_len);
    arp->htype = htons(ARP_HTYPE_ETHERNET);
    arp->ptype = htons(ARP_PTYPE_IPV4);
    arp->hlen = ARP_HLEN_ETHERNET;
    arp->plen = ARP_PLEN_IPV4;
    arp->opcode = htons(ARP_OP_REPLY);

    std::memcpy(arp->sender_mac, sender_mac.bytes, 6);
    arp->sender_ip = sender_ip.to_net_order();
    std::memcpy(arp->target_mac, target_mac.bytes, 6);
    arp->target_ip = target_ip.to_net_order();

    size_t total_len = l2_hdr_len + sizeof(arp_header_t);
    if (total_len < MIN_ETHERNET_FRAME_SIZE && buffer_size >= MIN_ETHERNET_FRAME_SIZE) {
        std::memset(buffer + total_len, 0, MIN_ETHERNET_FRAME_SIZE - total_len);
        total_len = MIN_ETHERNET_FRAME_SIZE;
    }

    return total_len;
}

} // namespace router
