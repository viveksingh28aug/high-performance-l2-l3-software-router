#ifndef ROUTER_PACKET_IO_H
#define ROUTER_PACKET_IO_H

#include "router/types.h"
#include <string>
#include <deque>
#include <vector>
#include <memory>

namespace router {

/**
 * @brief Abstract interface for packet capture and transmission.
 */
class PacketIO {
public:
    virtual ~PacketIO() = default;

    virtual bool open() = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;

    /**
     * @brief Polls for an ingress packet (non-blocking).
     * @return true if packet received into out_pkt, false if no packet available or error.
     */
    virtual bool receive(packet_buffer_t& out_pkt) = 0;

    /**
     * @brief Transmits an egress packet.
     * @return true if successfully transmitted, false on error.
     */
    virtual bool transmit(const packet_buffer_t& pkt) = 0;
};

/**
 * @brief Offline in-memory Packet IO backend for test fixtures and safe simulation.
 * 
 * Default operational mode that guarantees no modification to host network traffic.
 */
class OfflinePacketIO : public PacketIO {
public:
    explicit OfflinePacketIO(interface_id_t iface_id = 1);
    ~OfflinePacketIO() override = default;

    bool open() override { is_open_ = true; return true; }
    void close() override { is_open_ = false; }
    bool is_open() const override { return is_open_; }

    bool receive(packet_buffer_t& out_pkt) override;
    bool transmit(const packet_buffer_t& pkt) override;

    // Simulation helpers
    void inject_packet(const packet_buffer_t& pkt);
    const std::vector<packet_buffer_t>& transmitted_packets() const noexcept { return tx_history_; }
    void clear_history() noexcept { tx_history_.clear(); }
    size_t rx_queue_size() const noexcept { return rx_queue_.size(); }

private:
    interface_id_t iface_id_;
    bool is_open_{true};
    std::deque<packet_buffer_t> rx_queue_;
    std::vector<packet_buffer_t> tx_history_;
};

/**
 * @brief Linux AF_PACKET raw socket backend for live wire processing.
 * 
 * Requires CAP_NET_RAW capability or root execution.
 */
class AfPacketIO : public PacketIO {
public:
    AfPacketIO(std::string iface_name, interface_id_t iface_id);
    ~AfPacketIO() override;

    // Disallow copy
    AfPacketIO(const AfPacketIO&) = delete;
    AfPacketIO& operator=(const AfPacketIO&) = delete;

    bool open() override;
    void close() override;
    bool is_open() const override { return socket_fd_ >= 0; }

    bool receive(packet_buffer_t& out_pkt) override;
    bool transmit(const packet_buffer_t& pkt) override;

    const std::string& interface_name() const noexcept { return iface_name_; }
    int socket_fd() const noexcept { return socket_fd_; }

    /**
     * @brief Checks if current process has sufficient privilege for AF_PACKET.
     */
    static bool check_privileges() noexcept;

private:
    std::string iface_name_;
    interface_id_t iface_id_;
    int socket_fd_{-1};
    int ifindex_{-1};
};

} // namespace router

#endif // ROUTER_PACKET_IO_H
