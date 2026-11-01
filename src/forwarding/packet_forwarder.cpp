#include "router/packet_forwarder.h"
#include <iostream>

namespace router {

PacketForwarder::PacketForwarder() = default;

bool PacketForwarder::add_interface(const network_interface_t& iface) {
    if (iface.id == INVALID_INTERFACE_ID || iface.name.empty()) {
        return false;
    }
    interfaces_[iface.id] = iface;
    iface_name_to_id_[iface.name] = iface.id;

    // Automatically install connected route for interface subnet (Cisco IOS / Linux style)
    if (!iface.ip_addr.is_zero() && !iface.netmask.is_zero()) {
        ipv4_address_t subnet(iface.ip_addr.addr & iface.netmask.addr);
        uint8_t prefix_len = RoutingTable::mask_to_prefix_len(iface.netmask);
        routing_table_.add_route(subnet, prefix_len, ipv4_address_t::any(), iface.id, 0);
    }
    return true;
}

const network_interface_t* PacketForwarder::get_interface(interface_id_t id) const noexcept {
    auto it = interfaces_.find(id);
    if (it != interfaces_.end()) {
        return &it->second;
    }
    return nullptr;
}

const network_interface_t* PacketForwarder::get_interface_by_name(const std::string& name) const noexcept {
    auto it = iface_name_to_id_.find(name);
    if (it != iface_name_to_id_.end()) {
        return get_interface(it->second);
    }
    return nullptr;
}

bool PacketForwarder::is_router_interface_ip(ipv4_address_t ip) const noexcept {
    for (const auto& kv : interfaces_) {
        if (kv.second.ip_addr == ip) {
            return true;
        }
    }
    return false;
}

bool PacketForwarder::process_packet(packet_buffer_t& rx_pkt, std::vector<packet_buffer_t>& tx_pkts) {
    ++stats_.rx_packets;
    stats_.rx_bytes += rx_pkt.length;

    const auto* ingress_iface = get_interface(rx_pkt.ingress_interface_id);
    if (ingress_iface == nullptr || !ingress_iface->is_up) {
        return false;
    }

    // L2 Frame Parsing & Validation
    auto eth_res = parse_ethernet_frame(rx_pkt.data, rx_pkt.length);
    if (eth_res.error != ethernet_error_t::SUCCESS) {
        if (eth_res.error == ethernet_error_t::FRAME_TOO_SHORT) {
            ++stats_.l2_frame_too_short;
        } else if (eth_res.error == ethernet_error_t::FRAME_TOO_LONG) {
            ++stats_.l2_frame_too_long;
        }
        return false;
    }

    if (eth_res.has_vlan) {
        ++stats_.l2_vlan_tagged_packets;
    }

    // Destination MAC validation (Router interface MAC or Broadcast/Multicast)
    if (eth_res.dst_mac.is_broadcast()) {
        ++stats_.l2_broadcast_packets;
    } else if (eth_res.dst_mac.is_multicast()) {
        ++stats_.l2_multicast_packets;
    } else if (eth_res.dst_mac != ingress_iface->mac_addr) {
        ++stats_.l2_dst_mac_mismatch;
        return false;
    }

    // Protocol Demultiplexing
    if (eth_res.ethertype == ETHERTYPE_ARP) {
        return handle_arp_packet(rx_pkt, eth_res, ingress_iface, tx_pkts);
    } else if (eth_res.ethertype == ETHERTYPE_IPV4) {
        return handle_ipv4_packet(rx_pkt, eth_res, ingress_iface, tx_pkts);
    } else {
        ++stats_.l2_unsupported_ethertype;
        return false;
    }
}

bool PacketForwarder::handle_arp_packet(const packet_buffer_t& rx_pkt,
                                        const ethernet_parse_result_t& eth_res,
                                        const network_interface_t* ingress_iface,
                                        std::vector<packet_buffer_t>& tx_pkts) {
    auto arp_res = parse_arp_packet(rx_pkt.data + eth_res.l3_offset, eth_res.l3_length);
    if (arp_res.error != arp_error_t::SUCCESS) {
        return false;
    }

    if (arp_res.opcode == ARP_OP_REQUEST) {
        ++stats_.arp_requests_received;

        // Learn neighbor MAC and IP
        arp_cache_.update(arp_res.sender_ip, arp_res.sender_mac);

        // Check if ARP Request is querying this router interface IP
        if (arp_res.target_ip == ingress_iface->ip_addr) {
            packet_buffer_t reply_pkt;
            uint16_t vlan_id = eth_res.has_vlan ? eth_res.vlan.vid : 0;
            size_t reply_len = create_arp_reply_frame(
                reply_pkt.data, MAX_PACKET_SIZE,
                ingress_iface->mac_addr, ingress_iface->ip_addr,
                arp_res.sender_mac, arp_res.sender_ip, vlan_id);

            if (reply_len > 0) {
                reply_pkt.length = reply_len;
                reply_pkt.ingress_interface_id = ingress_iface->id;
                reply_pkt.egress_interface_id = ingress_iface->id;
                tx_pkts.push_back(reply_pkt);

                ++stats_.arp_replies_sent;
                ++stats_.tx_packets;
                stats_.tx_bytes += reply_len;
                return true;
            }
        }
    } else if (arp_res.opcode == ARP_OP_REPLY) {
        ++stats_.arp_replies_received;

        // Cache resolved entry
        arp_cache_.update(arp_res.sender_ip, arp_res.sender_mac);

        // Flush and forward any pending packets buffered for this IP
        auto pending = arp_cache_.dequeue_pending_packets(arp_res.sender_ip);
        for (auto& pkt : pending) {
            auto queued_eth_res = parse_ethernet_frame(pkt.data, pkt.length);
            if (queued_eth_res.error != ethernet_error_t::SUCCESS) {
                continue;
            }

            auto queued_ip_res = parse_ipv4_packet(pkt.data + queued_eth_res.l3_offset, queued_eth_res.l3_length);
            if (queued_ip_res.error != ipv4_error_t::SUCCESS || queued_ip_res.ttl <= 1) {
                continue;
            }

            route_entry_t route;
            if (!routing_table_.lookup_fast(queued_ip_res.dst_ip, &route)) {
                continue;
            }

            const auto* egress_iface = get_interface(route.interface_id);
            if (egress_iface == nullptr || !egress_iface->is_up) {
                continue;
            }

            // Decrement TTL & update checksum
            decrement_ipv4_ttl(pkt.data + queued_eth_res.l3_offset, queued_eth_res.l3_length);

            // Rewrite L2 frame header
            rewrite_ethernet_header(pkt.data, pkt.length, arp_res.sender_mac, egress_iface->mac_addr);

            pkt.egress_interface_id = egress_iface->id;
            tx_pkts.push_back(pkt);

            ++stats_.arp_pending_dequeued;
            ++stats_.l3_forwarded;
            ++stats_.tx_packets;
            stats_.tx_bytes += pkt.length;
        }
        return true;
    }

    return true;
}

bool PacketForwarder::handle_ipv4_packet(packet_buffer_t& rx_pkt,
                                         const ethernet_parse_result_t& eth_res,
                                         const network_interface_t* ingress_iface,
                                         std::vector<packet_buffer_t>& tx_pkts) {
    (void)ingress_iface;
    ++stats_.l3_ipv4_packets;

    auto ip_res = parse_ipv4_packet(rx_pkt.data + eth_res.l3_offset, eth_res.l3_length);
    if (ip_res.error != ipv4_error_t::SUCCESS) {
        switch (ip_res.error) {
            case ipv4_error_t::CHECKSUM_ERROR:
                ++stats_.l3_checksum_errors;
                break;
            case ipv4_error_t::INVALID_VERSION:
                ++stats_.l3_invalid_version;
                break;
            case ipv4_error_t::INVALID_IHL:
                ++stats_.l3_invalid_ihl;
                break;
            case ipv4_error_t::TOTAL_LENGTH_TOO_SHORT:
            case ipv4_error_t::PACKET_TRUNCATED:
            case ipv4_error_t::HEADER_TOO_SHORT:
                ++stats_.l3_length_mismatch;
                break;
            default:
                break;
        }
        return false;
    }

    // Check for local router termination
    if (is_router_interface_ip(ip_res.dst_ip)) {
        ++stats_.l3_local_delivered;
        return true;
    }

    // TTL Check: must be > 1 to forward
    if (ip_res.ttl <= 1) {
        ++stats_.l3_ttl_expired;
        return false;
    }

    // LPM Routing Lookup
    route_entry_t route;
    if (!routing_table_.lookup_fast(ip_res.dst_ip, &route)) {
        ++stats_.l3_no_route;
        return false;
    }

    const auto* egress_iface = get_interface(route.interface_id);
    if (egress_iface == nullptr || !egress_iface->is_up) {
        ++stats_.l3_no_route;
        return false;
    }

    // Determine target next-hop IP (destination IP if direct subnet, else gateway)
    ipv4_address_t next_hop_ip = route.is_direct() ? ip_res.dst_ip : route.next_hop;

    // ARP Resolution
    mac_address_t next_hop_mac;
    if (arp_cache_.resolve(next_hop_ip, &next_hop_mac)) {
        // Fast-path forwarding
        ++stats_.arp_cache_hits;

        // 1. Decrement TTL and incrementally update checksum
        decrement_ipv4_ttl(rx_pkt.data + eth_res.l3_offset, eth_res.l3_length);

        // 2. Rewrite L2 header: dst = next-hop MAC, src = egress interface MAC
        rewrite_ethernet_header(rx_pkt.data, rx_pkt.length, next_hop_mac, egress_iface->mac_addr);

        rx_pkt.egress_interface_id = egress_iface->id;
        tx_pkts.push_back(rx_pkt);

        ++stats_.l3_forwarded;
        ++stats_.tx_packets;
        stats_.tx_bytes += rx_pkt.length;
        return true;
    }

    // ARP Cache Miss: buffer packet in pending queue and trigger ARP Request
    ++stats_.arp_cache_misses;
    if (arp_cache_.queue_pending_packet(next_hop_ip, rx_pkt)) {
        ++stats_.arp_pending_queued;
    } else {
        ++stats_.arp_pending_dropped_full;
    }

    packet_buffer_t arp_req_pkt;
    uint16_t vlan_id = eth_res.has_vlan ? eth_res.vlan.vid : 0;
    size_t req_len = create_arp_request_frame(
        arp_req_pkt.data, MAX_PACKET_SIZE,
        egress_iface->mac_addr, egress_iface->ip_addr, next_hop_ip, vlan_id);

    if (req_len > 0) {
        arp_req_pkt.length = req_len;
        arp_req_pkt.ingress_interface_id = egress_iface->id;
        arp_req_pkt.egress_interface_id = egress_iface->id;
        tx_pkts.push_back(arp_req_pkt);

        ++stats_.arp_requests_sent;
        ++stats_.tx_packets;
        stats_.tx_bytes += req_len;
    }

    return true;
}

void PacketForwarder::periodic_maintenance() {
    auto sweep_res = arp_cache_.sweep();
    stats_.arp_pending_dropped_timeout += sweep_res.second;
}

} // namespace router
