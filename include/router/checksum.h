#ifndef ROUTER_CHECKSUM_H
#define ROUTER_CHECKSUM_H

#include <cstdint>
#include <cstddef>

namespace router {

/**
 * @brief Computes standard RFC 1071 Internet Checksum.
 * 
 * Computes the 16-bit one's complement sum of 16-bit words.
 * Returns the inverted (1's complement) sum in network byte order.
 * 
 * @param data Pointer to buffer to checksum.
 * @param length Length of buffer in bytes.
 * @return 16-bit checksum in network byte order.
 */
uint16_t calculate_checksum(const void* data, size_t length) noexcept;

/**
 * @brief Verifies whether the checksum of a packet header is valid.
 * 
 * A valid RFC 1071 checksum over a header (with checksum field populated)
 * results in a 16-bit sum of 0xFFFF (or 0 when inverted).
 * 
 * @param data Pointer to header.
 * @param length Length of header in bytes.
 * @return true if valid, false otherwise.
 */
bool verify_checksum(const void* data, size_t length) noexcept;

/**
 * @brief RFC 1624 Algorithm 3: Incremental Checksum Update for modified 16-bit word.
 * 
 * Efficiently computes updated checksum when a 16-bit field changes,
 * avoiding a full header re-checksum in the router fast path.
 * 
 * Formula: HC' = ~(~HC + ~m + m')
 * 
 * @param old_checksum Old 16-bit checksum (network byte order).
 * @param old_word Old 16-bit value (network byte order).
 * @param new_word New 16-bit value (network byte order).
 * @return Updated 16-bit checksum (network byte order).
 */
uint16_t checksum_update16(uint16_t old_checksum, uint16_t old_word, uint16_t new_word) noexcept;

/**
 * @brief Incremental update specifically for IPv4 TTL decrement.
 * 
 * IPv4 header word at byte offset 8 consists of [TTL (8 bits) | Protocol (8 bits)] in network order.
 * 
 * @param old_checksum Current IPv4 header checksum (network byte order).
 * @param old_ttl Original TTL value.
 * @param new_ttl Decremented TTL value (typically old_ttl - 1).
 * @param protocol Protocol field value (e.g., 6 for TCP, 17 for UDP, 1 for ICMP).
 * @return Updated IPv4 header checksum (network byte order).
 */
uint16_t checksum_update_ttl(uint16_t old_checksum, uint8_t old_ttl, uint8_t new_ttl, uint8_t protocol) noexcept;

} // namespace router

#endif // ROUTER_CHECKSUM_H
