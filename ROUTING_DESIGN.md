# Routing Design & Longest Prefix Matching (LPM)

This document provides a technical breakdown of the routing architecture, algorithmic Longest Prefix Match (LPM) binary trie, branch pruning mechanism, and comparison with hardware routing silicon (e.g., Cisco Silicon One FIB engines).

> **Note**: This project implements an algorithmic CPU-based binary trie designed to demonstrate LPM concepts in software. It is an educational and architectural reference, not an ASIC-level microcode implementation.

---

## 1. The Longest Prefix Match Problem

In IPv4 routing, destination IP addresses are mapped to forwarding destinations based on network prefixes. Because routing tables frequently contain overlapping subnets (e.g., a default gateway `0.0.0.0/0`, a regional aggregation `10.0.0.0/8`, a campus network `10.1.0.0/16`, and a host route `10.1.2.5/32`), the router must forward packets according to the **longest matching prefix** (the most specific route).

```
Destination: 10.1.2.5

Prefix Match Candidates:
1. 0.0.0.0/0      (len = 0)  -> Gi0/0/1 (GW 10.0.0.2)
2. 10.0.0.0/8     (len = 8)  -> Gi0/0/2 (Core Switch)
3. 10.1.0.0/16    (len = 16) -> Gi0/0/3 (Building B)
4. 10.1.2.0/24    (len = 24) -> Gi0/0/4 (Server VLAN)
5. 10.1.2.5/32    (len = 32) -> Direct Host (Fastest Path)

Selected Route: 10.1.2.5/32 (Longest Prefix Length = 32)
```

---

## 2. Binary Trie Data Structure

The router implements an uncompressed binary radix trie where each level $d \in [0, 31]$ represents a 1-bit branching decision corresponding to bit $(31 - d)$ of the IPv4 address:

```
                          [ Root (/0 Default Route) ]
                                 /          \
                           bit 0/            \bit 1
                               /              \
                          [Node]              [Node]
                          /    \              /    \
                        0/      \1          0/      \1
                       ...      ...        ...      ...
```

### 2.1 Node Representation

```cpp
struct lpm_node_t {
    lpm_node_t* children[2]{nullptr, nullptr}; // 0 = left, 1 = right
    bool has_route{false};
    route_entry_t route{};
};
```

- Each node contains exactly two pointer slots (`children[0]` and `children[1]`).
- If a route terminates at that prefix, `has_route` is set to `true`, and `route` stores the next-hop IP, egress interface ID, and metric.
- Intermediate routing nodes that exist solely to guide bit branching have `has_route == false`.

### 2.2 Algorithmic Complexities

| Operation | Time Complexity | Space Complexity (Worst Case) | Notes |
| :--- | :--- | :--- | :--- |
| **Lookup** | $O(W) \le 32$ | $O(1)$ | Deterministic upper bound, cache-friendly |
| **Insertion** | $O(W) \le 32$ | $O(W)$ nodes | Allocates at most 32 nodes for a new /32 |
| **Deletion** | $O(W) \le 32$ | $O(1)$ auxiliary | Prunes unused intermediate branches |

*Where $W = 32$ is the width of an IPv4 address in bits.*

---

## 3. Core Algorithms

### 3.1 Longest Prefix Match Lookup

The lookup function traverses the trie starting from `root_`:
1. If the current node has `has_route == true`, record it as `best_match`.
2. Inspect bit $(31 - d)$ of the destination IP address:
   $$\text{bit} = (\text{dest\_ip} \gg (31 - d)) \ \& \ 1$$
3. Transition to `current = current->children[bit]`.
4. If `current == nullptr`, terminate traversal.
5. Repeat until bit 31 is checked or a null pointer is encountered.
6. If `best_match != nullptr`, copy the matched route entry and return `true`; otherwise return `false`.

```cpp
bool LpmTrie::lookup(ipv4_address_t dest_ip, route_entry_t* out_route) const noexcept {
    const lpm_node_t* current = root_;
    const route_entry_t* best_match = nullptr;

    if (current->has_route) {
        best_match = &current->route;
    }

    for (uint8_t depth = 0; depth < 32; ++depth) {
        uint8_t bit = static_cast<uint8_t>((dest_ip.addr >> (31 - depth)) & 1);
        current = current->children[bit];
        if (current == nullptr) break;
        if (current->has_route) {
            best_match = &current->route;
        }
    }

    if (best_match != nullptr) {
        if (out_route) *out_route = *best_match;
        return true;
    }
    return false;
}
```

### 3.2 Insertion with Route Replacement

When inserting a route $(P, L)$:
1. Mask the prefix: $P_{\text{masked}} = P \ \& \ (\sim 0U \ll (32 - L))$.
2. If $L = 0$, update `root_` directly (Default Route).
3. Otherwise, traverse $L$ bits. Allocate child nodes along the path if they do not yet exist.
4. At the target node, set `has_route = true`, store the route payload, and increment the active route counter.

### 3.3 Deletion with Automatic Branch Pruning

A major pitfall in naive trie implementations is **memory leaking through abandoned branches**: when a route is deleted, intermediate nodes that only existed to support that route remain allocated indefinitely.

Our implementation uses post-order recursive branch pruning:
1. Traverse down to depth $L$.
2. Clear `node->has_route = false`.
3. Check if the node has become an orphaned leaf:
   $$\text{node} \neq \text{root\_} \ \land \ \neg\text{node->has\_route} \ \land \ \text{children}[0] = \text{nullptr} \ \land \ \text{children}[1] = \text{nullptr}$$
4. If true, delete the node, set the parent's pointer to `nullptr`, and decrement `node_count_`.
5. Propagate pruning up the call chain to clean ancestral orphan nodes.

---

## 4. Hardware Comparison & Educational Context

| Feature | Software Binary Trie (This Project) | Cisco Silicon One / Hardware ASIC |
| :--- | :--- | :--- |
| **Lookup Mechanism** | Bitwise pointer traversal in CPU L1/L2 cache | TCAM (Ternary Content Addressable Memory) + Multi-bit Trie / Tree-Bitmap |
| **Cycles per Lookup** | 10 to 50 CPU cycles (~9 to 50 nanoseconds) | Single clock cycle (~1 nanosecond) |
| **Throughput** | 10 to 45 Mpps per CPU core | 10 to 50 Billion packets per second (Tbps switching) |
| **Memory Footprint** | ~32 bytes per trie node in DRAM/SRAM | TCAM cells with parallel mask and comparator gates |
| **Update Latency** | Microseconds (dynamic node insertion/pruning) | Hardware TCAM write cycles or algorithmic shadow FIB swap |
| **Prefix Support** | Arbitrary IPv4 prefixes (/0 to /32) | Hardware programmed LPM / FIB tables |
