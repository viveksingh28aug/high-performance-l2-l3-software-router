#ifndef ROUTER_ROUTING_TABLE_H
#define ROUTER_ROUTING_TABLE_H

#include "router/types.h"
#include "router/lpm_trie.h"
#include <string>
#include <vector>
#include <optional>

namespace router {

class RoutingTable {
public:
    RoutingTable() = default;
    ~RoutingTable() = default;

    /**
     * @brief Adds or updates a route with explicit prefix and prefix length.
     */
    bool add_route(ipv4_address_t prefix, uint8_t prefix_len,
                   ipv4_address_t next_hop, interface_id_t interface_id,
                   uint32_t metric = 0);

    /**
     * @brief Adds or updates a route using a subnet mask instead of prefix length.
     */
    bool add_route_with_mask(ipv4_address_t prefix, ipv4_address_t netmask,
                            ipv4_address_t next_hop, interface_id_t interface_id,
                            uint32_t metric = 0);

    /**
     * @brief Adds or updates a route from a CIDR notation string (e.g. "192.168.1.0/24").
     */
    bool add_route_cidr(const std::string& cidr, ipv4_address_t next_hop,
                        interface_id_t interface_id, uint32_t metric = 0);

    /**
     * @brief Sets the default route (0.0.0.0/0).
     */
    bool set_default_route(ipv4_address_t next_hop, interface_id_t interface_id, uint32_t metric = 0);

    /**
     * @brief Removes a route matching prefix and prefix length.
     */
    bool delete_route(ipv4_address_t prefix, uint8_t prefix_len);

    /**
     * @brief Removes a default route.
     */
    bool delete_default_route();

    /**
     * @brief Performs Longest Prefix Match lookup for a destination IP.
     */
    std::optional<route_entry_t> lookup(ipv4_address_t dest_ip) const noexcept;

    /**
     * @brief Longest Prefix Match lookup with direct pointer output for zero-overhead fast-path.
     */
    bool lookup_fast(ipv4_address_t dest_ip, route_entry_t* out_route) const noexcept {
        return trie_.lookup(dest_ip, out_route);
    }

    /**
     * @brief Clears all routes from the table.
     */
    void clear() noexcept {
        trie_.clear();
    }

    /**
     * @brief Returns the total number of routes.
     */
    size_t size() const noexcept {
        return trie_.size();
    }

    /**
     * @brief Returns total nodes allocated in the underlying trie.
     */
    size_t node_count() const noexcept {
        return trie_.node_count();
    }

    /**
     * @brief Returns a snapshot of all active routes.
     */
    std::vector<route_entry_t> get_all_routes() const {
        return trie_.get_all_routes();
    }

    /**
     * @brief Converts a 32-bit subnet mask to prefix length. Returns 0 if mask is invalid.
     */
    static uint8_t mask_to_prefix_len(ipv4_address_t mask) noexcept;

    /**
     * @brief Converts a prefix length (0-32) to a subnet mask.
     */
    static ipv4_address_t prefix_len_to_mask(uint8_t prefix_len) noexcept;

private:
    LpmTrie trie_;
};

} // namespace router

#endif // ROUTER_ROUTING_TABLE_H
