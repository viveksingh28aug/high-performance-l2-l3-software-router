#include "router/routing_table.h"
#include <cstdio>
#include <string>

namespace router {

uint8_t RoutingTable::mask_to_prefix_len(ipv4_address_t mask) noexcept {
    if (mask.addr == 0) {
        return 0;
    }
    if (mask.addr == 0xFFFFFFFF) {
        return 32;
    }
    uint32_t inverted = ~mask.addr;
    int lz = __builtin_clz(inverted);
    uint8_t len = static_cast<uint8_t>(lz);

    // Verify it is a valid contiguous netmask
    uint32_t expected = (len == 0) ? 0 : (~0U << (32 - len));
    if (mask.addr != expected) {
        return 0; // Non-contiguous mask
    }
    return len;
}

ipv4_address_t RoutingTable::prefix_len_to_mask(uint8_t prefix_len) noexcept {
    if (prefix_len == 0) {
        return ipv4_address_t(0);
    }
    if (prefix_len >= 32) {
        return ipv4_address_t(0xFFFFFFFF);
    }
    return ipv4_address_t(~0U << (32 - prefix_len));
}

bool RoutingTable::add_route(ipv4_address_t prefix, uint8_t prefix_len,
                             ipv4_address_t next_hop, interface_id_t interface_id,
                             uint32_t metric) {
    if (prefix_len > 32) {
        return false;
    }
    route_entry_t entry;
    entry.prefix = prefix;
    entry.prefix_len = prefix_len;
    entry.next_hop = next_hop;
    entry.interface_id = interface_id;
    entry.metric = metric;
    return trie_.insert(entry);
}

bool RoutingTable::add_route_with_mask(ipv4_address_t prefix, ipv4_address_t netmask,
                                      ipv4_address_t next_hop, interface_id_t interface_id,
                                      uint32_t metric) {
    uint8_t prefix_len = mask_to_prefix_len(netmask);
    return add_route(prefix, prefix_len, next_hop, interface_id, metric);
}

bool RoutingTable::add_route_cidr(const std::string& cidr, ipv4_address_t next_hop,
                                 interface_id_t interface_id, uint32_t metric) {
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) {
        // Assume host route /32
        ipv4_address_t ip = ipv4_address_t::from_string(cidr);
        return add_route(ip, 32, next_hop, interface_id, metric);
    }

    std::string ip_part = cidr.substr(0, slash_pos);
    std::string len_part = cidr.substr(slash_pos + 1);

    ipv4_address_t ip = ipv4_address_t::from_string(ip_part);
    unsigned int len = 0;
    if (std::sscanf(len_part.c_str(), "%u", &len) != 1 || len > 32) {
        return false;
    }

    return add_route(ip, static_cast<uint8_t>(len), next_hop, interface_id, metric);
}

bool RoutingTable::set_default_route(ipv4_address_t next_hop, interface_id_t interface_id, uint32_t metric) {
    return add_route(ipv4_address_t(0), 0, next_hop, interface_id, metric);
}

bool RoutingTable::delete_route(ipv4_address_t prefix, uint8_t prefix_len) {
    return trie_.remove(prefix, prefix_len);
}

bool RoutingTable::delete_default_route() {
    return trie_.remove(ipv4_address_t(0), 0);
}

std::optional<route_entry_t> RoutingTable::lookup(ipv4_address_t dest_ip) const noexcept {
    route_entry_t route;
    if (trie_.lookup(dest_ip, &route)) {
        return route;
    }
    return std::nullopt;
}

} // namespace router
