#include "router/lpm_trie.h"
#include <utility>

namespace router {

LpmTrie::LpmTrie() {
    root_ = new lpm_node_t();
    node_count_ = 1;
}

LpmTrie::~LpmTrie() {
    clear();
    delete root_;
    root_ = nullptr;
}

LpmTrie::LpmTrie(LpmTrie&& other) noexcept
    : root_(other.root_), count_(other.count_), node_count_(other.node_count_) {
    other.root_ = new lpm_node_t();
    other.count_ = 0;
    other.node_count_ = 1;
}

LpmTrie& LpmTrie::operator=(LpmTrie&& other) noexcept {
    if (this != &other) {
        clear();
        delete root_;

        root_ = other.root_;
        count_ = other.count_;
        node_count_ = other.node_count_;

        other.root_ = new lpm_node_t();
        other.count_ = 0;
        other.node_count_ = 1;
    }
    return *this;
}

void LpmTrie::destroy_subtree(lpm_node_t* node) noexcept {
    if (node == nullptr) {
        return;
    }
    if (node->children[0] != nullptr) {
        destroy_subtree(node->children[0]);
        delete node->children[0];
        node->children[0] = nullptr;
    }
    if (node->children[1] != nullptr) {
        destroy_subtree(node->children[1]);
        delete node->children[1];
        node->children[1] = nullptr;
    }
}

void LpmTrie::clear() noexcept {
    if (root_ != nullptr) {
        destroy_subtree(root_->children[0]);
        delete root_->children[0];
        root_->children[0] = nullptr;

        destroy_subtree(root_->children[1]);
        delete root_->children[1];
        root_->children[1] = nullptr;

        root_->has_route = false;
        root_->route = route_entry_t{};
    }
    count_ = 0;
    node_count_ = 1; // Root remains
}

bool LpmTrie::insert(const route_entry_t& route) {
    if (route.prefix_len > 32) {
        return false;
    }

    uint32_t mask = (route.prefix_len == 0) ? 0 : (~0U << (32 - route.prefix_len));
    uint32_t masked_prefix = route.prefix.addr & mask;

    lpm_node_t* current = root_;

    for (uint8_t depth = 0; depth < route.prefix_len; ++depth) {
        uint8_t bit = static_cast<uint8_t>((masked_prefix >> (31 - depth)) & 1);
        if (current->children[bit] == nullptr) {
            current->children[bit] = new lpm_node_t();
            ++node_count_;
        }
        current = current->children[bit];
    }

    if (!current->has_route) {
        ++count_;
    }

    current->has_route = true;
    current->route = route;
    current->route.prefix = ipv4_address_t(masked_prefix);
    current->route.prefix_len = route.prefix_len;

    return true;
}

bool LpmTrie::remove_helper(lpm_node_t*& node, uint32_t prefix, uint8_t prefix_len, uint8_t depth, bool& removed) {
    if (node == nullptr) {
        return false;
    }

    if (depth == prefix_len) {
        if (node->has_route) {
            node->has_route = false;
            node->route = route_entry_t{};
            removed = true;
            --count_;
        }
    } else {
        uint8_t bit = static_cast<uint8_t>((prefix >> (31 - depth)) & 1);
        remove_helper(node->children[bit], prefix, prefix_len, static_cast<uint8_t>(depth + 1), removed);
    }

    // Prune node if it has no route and no children, and is not the root
    if (node != root_ && !node->has_route && node->children[0] == nullptr && node->children[1] == nullptr) {
        delete node;
        node = nullptr;
        --node_count_;
    }

    return removed;
}

bool LpmTrie::remove(ipv4_address_t prefix, uint8_t prefix_len) {
    if (prefix_len > 32 || root_ == nullptr) {
        return false;
    }

    uint32_t mask = (prefix_len == 0) ? 0 : (~0U << (32 - prefix_len));
    uint32_t masked_prefix = prefix.addr & mask;

    bool removed = false;
    remove_helper(root_, masked_prefix, prefix_len, 0, removed);
    return removed;
}

bool LpmTrie::lookup(ipv4_address_t dest_ip, route_entry_t* out_route) const noexcept {
    if (root_ == nullptr) {
        return false;
    }

    const lpm_node_t* current = root_;
    const route_entry_t* best_match = nullptr;

    if (current->has_route) {
        best_match = &current->route;
    }

    for (uint8_t depth = 0; depth < 32; ++depth) {
        uint8_t bit = static_cast<uint8_t>((dest_ip.addr >> (31 - depth)) & 1);
        current = current->children[bit];
        if (current == nullptr) {
            break;
        }
        if (current->has_route) {
            best_match = &current->route;
        }
    }

    if (best_match != nullptr) {
        if (out_route != nullptr) {
            *out_route = *best_match;
        }
        return true;
    }

    return false;
}

void LpmTrie::collect_routes(const lpm_node_t* node, std::vector<route_entry_t>& routes) const {
    if (node == nullptr) {
        return;
    }
    if (node->has_route) {
        routes.push_back(node->route);
    }
    collect_routes(node->children[0], routes);
    collect_routes(node->children[1], routes);
}

std::vector<route_entry_t> LpmTrie::get_all_routes() const {
    std::vector<route_entry_t> routes;
    collect_routes(root_, routes);
    return routes;
}

} // namespace router
