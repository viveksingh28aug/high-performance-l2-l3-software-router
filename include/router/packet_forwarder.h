#ifndef ROUTER_PACKET_FORWARDER_H
#define ROUTER_PACKET_FORWARDER_H

#include "router/types.h"
#include "router/ethernet.h"
#include "router/ipv4.h"
#include "router/arp.h"
#include "router/routing_table.h"
#include <vector>
#include <unordered_map>
#include <memory>

namespace router {

class PacketForwarder {
public:
    PacketForwarder();
    ~PacketForwarder() = default;

    /**
     * @brief Registers a network interface with the forwarder.
     */
    bool add_interface(const network_interface_t& iface);

    /**
     * @brief Retrieves an interface by ID.
     */
    const network_interface_t* get_interface(interface_id_t id) const noexcept;

    /**
     * @brief Retrieves an interface by name.
     */
    const network_interface_t* get_interface_by_name(const std::string& name) const noexcept;

    /**
     * @brief Core packet processing pipeline.
     * 
     * Ingests an incoming packet, parses L2 and L3, executes LPM routing lookup,
     * resolves next-hop ARP, rewrites headers, and generates output packets (forwarded IPv4,
     * synthesized ARP requests/replies).
     * 
     * @param rx_pkt Ingress packet buffer.
     * @param tx_pkts Output vector where packets to be transmitted are appended.
     * @return true if packet was handled, false if dropped due to validation error.
     */
    bool process_packet(packet_buffer_t& rx_pkt, std::vector<packet_buffer_t>& tx_pkts);

    /**
     * @brief Runs periodic maintenance (e.g. ARP table aging and pending queue cleanup).
     */
    void periodic_maintenance();

    /**
     * @brief Access routing table for configuration.
     */
    RoutingTable& routing_table() noexcept { return routing_table_; }
    const RoutingTable& routing_table() const noexcept { return routing_table_; }

    /**
     * @brief Access ARP cache for testing / inspection.
     */
    ArpCache& arp_cache() noexcept { return arp_cache_; }
    const ArpCache& arp_cache() const noexcept { return arp_cache_; }

    /**
     * @brief Access router statistics counters.
     */
    const router_stats_t& stats() const noexcept { return stats_; }
    void reset_stats() noexcept { stats_.reset(); }

private:
    std::unordered_map<interface_id_t, network_interface_t> interfaces_;
    std::unordered_map<std::string, interface_id_t> iface_name_to_id_;
    RoutingTable routing_table_;
    ArpCache arp_cache_;
    router_stats_t stats_;

    bool is_router_interface_ip(ipv4_address_t ip) const noexcept;
    bool handle_arp_packet(const packet_buffer_t& rx_pkt,
                           const ethernet_parse_result_t& eth_res,
                           const network_interface_t* ingress_iface,
                           std::vector<packet_buffer_t>& tx_pkts);
    bool handle_ipv4_packet(packet_buffer_t& rx_pkt,
                            const ethernet_parse_result_t& eth_res,
                            const network_interface_t* ingress_iface,
                            std::vector<packet_buffer_t>& tx_pkts);
};

} // namespace router

#endif // ROUTER_PACKET_FORWARDER_H
