#ifndef ROUTER_LPM_TRIE_H
#define ROUTER_LPM_TRIE_H

#include "router/types.h"
#include <cstdint>
#include <cstddef>
#include <vector>

namespace router {

struct lpm_node_t {
    lpm_node_t* children[2]{nullptr, nullptr};
    bool has_route{false};
    route_entry_t route{};

    lpm_node_t() = default;
    ~lpm_node_t() = default;
};

class LpmTrie {
public:
    LpmTrie();
    ~LpmTrie();

    // Prevent copying to avoid accidental deep copy overhead in systems code
    LpmTrie(const LpmTrie&) = delete;
    LpmTrie& operator=(const LpmTrie&) = delete;

    // Enable move semantics
    LpmTrie(LpmTrie&& other) noexcept;
    LpmTrie& operator=(LpmTrie&& other) noexcept;

    /**
     * @brief Inserts or updates a route entry in the LPM binary trie.
     * 
     * @param route Route entry containing prefix, prefix length, next hop, interface, metric.
     * @return true if inserted or updated, false if prefix_len > 32.
     */
    bool insert(const route_entry_t& route);

    /**
     * @brief Removes a route entry matching prefix and prefix length, pruning unused branches.
     * 
     * @param prefix Network prefix to remove.
     * @param prefix_len Prefix length (0-32).
     * @return true if route was found and removed, false if not found.
     */
    bool remove(ipv4_address_t prefix, uint8_t prefix_len);

    /**
     * @brief Performs Longest Prefix Match lookup for a destination IPv4 address.
     * 
     * @param dest_ip Destination IPv4 address.
     * @param out_route Output pointer where matching route is copied if found.
     * @return true if a matching route (including default route if configured) was found, false otherwise.
     */
    bool lookup(ipv4_address_t dest_ip, route_entry_t* out_route) const noexcept;

    /**
     * @brief Returns total number of active routes in the trie.
     */
    size_t size() const noexcept { return count_; }

    /**
     * @brief Returns total number of trie nodes allocated (useful for memory profiling).
     */
    size_t node_count() const noexcept { return node_count_; }

    /**
     * @brief Clears all routes and frees all allocated nodes.
     */
    void clear() noexcept;

    /**
     * @brief Dumps all active routes into a vector.
     */
    std::vector<route_entry_t> get_all_routes() const;

private:
    lpm_node_t* root_{nullptr};
    size_t count_{0};
    size_t node_count_{0};

    void destroy_subtree(lpm_node_t* node) noexcept;
    bool remove_helper(lpm_node_t*& node, uint32_t prefix, uint8_t prefix_len, uint8_t depth, bool& removed);
    void collect_routes(const lpm_node_t* node, std::vector<route_entry_t>& routes) const;
};

} // namespace router

#endif // ROUTER_LPM_TRIE_H
