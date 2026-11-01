#include "router/packet_io.h"
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

namespace router {

// ---------------------------------------------------------------------------
// OfflinePacketIO Implementation
// ---------------------------------------------------------------------------

OfflinePacketIO::OfflinePacketIO(interface_id_t iface_id)
    : iface_id_(iface_id) {}

bool OfflinePacketIO::receive(packet_buffer_t& out_pkt) {
    if (!is_open_ || rx_queue_.empty()) {
        return false;
    }
    out_pkt = rx_queue_.front();
    rx_queue_.pop_front();
    out_pkt.ingress_interface_id = iface_id_;
    out_pkt.timestamp = std::chrono::steady_clock::now();
    return true;
}

bool OfflinePacketIO::transmit(const packet_buffer_t& pkt) {
    if (!is_open_) {
        return false;
    }
    tx_history_.push_back(pkt);
    return true;
}

void OfflinePacketIO::inject_packet(const packet_buffer_t& pkt) {
    packet_buffer_t copy = pkt;
    copy.ingress_interface_id = iface_id_;
    rx_queue_.push_back(copy);
}

// ---------------------------------------------------------------------------
// AfPacketIO Implementation
// ---------------------------------------------------------------------------

AfPacketIO::AfPacketIO(std::string iface_name, interface_id_t iface_id)
    : iface_name_(std::move(iface_name)), iface_id_(iface_id) {}

AfPacketIO::~AfPacketIO() {
    close();
}

bool AfPacketIO::check_privileges() noexcept {
    return (geteuid() == 0);
}

bool AfPacketIO::open() {
    if (socket_fd_ >= 0) {
        return true; // Already opened
    }

    if (!check_privileges()) {
        std::cerr << "[AF_PACKET WARNING] Process requires CAP_NET_RAW capability or root execution "
                  << "to open AF_PACKET raw socket on interface '" << iface_name_ << "'.\n"
                  << "Please run with sudo or setcap cap_net_raw+ep <binary> to enable live capture.\n";
        return false;
    }

    socket_fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd_ < 0) {
        std::cerr << "[AF_PACKET ERROR] Failed to create socket: " << std::strerror(errno) << "\n";
        return false;
    }

    // Set non-blocking socket I/O
    int flags = fcntl(socket_fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::cerr << "[AF_PACKET ERROR] Failed to set O_NONBLOCK: " << std::strerror(errno) << "\n";
        close();
        return false;
    }

    // Resolve interface name to index
    ifindex_ = static_cast<int>(if_nametoindex(iface_name_.c_str()));
    if (ifindex_ == 0) {
        std::cerr << "[AF_PACKET ERROR] Interface '" << iface_name_ << "' not found: "
                  << std::strerror(errno) << "\n";
        close();
        return false;
    }

    // Bind to interface
    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex_;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
        std::cerr << "[AF_PACKET ERROR] Failed to bind to interface '" << iface_name_
                  << "': " << std::strerror(errno) << "\n";
        close();
        return false;
    }

    return true;
}

void AfPacketIO::close() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
        ifindex_ = -1;
    }
}

bool AfPacketIO::receive(packet_buffer_t& out_pkt) {
    if (socket_fd_ < 0) {
        return false;
    }

    struct sockaddr_ll sll;
    socklen_t sll_len = sizeof(sll);

    ssize_t bytes_read = recvfrom(socket_fd_, out_pkt.data, MAX_PACKET_SIZE, 0,
                                  reinterpret_cast<struct sockaddr*>(&sll), &sll_len);

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false; // No packet available in non-blocking mode
        }
        return false;
    }

    out_pkt.length = static_cast<size_t>(bytes_read);
    out_pkt.ingress_interface_id = iface_id_;
    out_pkt.timestamp = std::chrono::steady_clock::now();
    return true;
}

bool AfPacketIO::transmit(const packet_buffer_t& pkt) {
    if (socket_fd_ < 0 || ifindex_ <= 0) {
        return false;
    }

    struct sockaddr_ll sll;
    std::memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex_;
    sll.sll_halen = 6;

    ssize_t sent = sendto(socket_fd_, pkt.data, pkt.length, 0,
                          reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll));

    return (sent == static_cast<ssize_t>(pkt.length));
}

} // namespace router
