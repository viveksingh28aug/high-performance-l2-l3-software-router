# Packet Forwarding Engine & Data Plane Pipeline

This document details the packet forwarding pipeline, frame validation, ARP neighbor resolution state machine, header rewriting mechanisms, and telemetry counters.

---

## 1. End-to-End Packet Processing Pipeline

```
+---------------------------------------------------------------------------------+
|                              PACKET INGRESS                                     |
|  Ingress Interface Identification -> Buffer Ingestion (Offline / AF_PACKET)     |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       STAGE 1: LAYER 2 VALIDATION                               |
|  1. Validate Frame Length (14 <= len <= 9022)                                   |
|  2. Parse 802.1Q / 802.1ad VLAN tags (extract VID, PCP, DEI, inner EtherType)   |
|  3. Validate Destination MAC:                                                   |
|     - Matches Interface MAC ?  -------> [PROCEED]                               |
|     - Broadcast / Multicast ? --------> [PROCEED]                               |
|     - Unicast Mismatch ? -------------> [DROP: l2_dst_mac_mismatch]             |
+----------------------------------------+----------------------------------------+
                                         |
                                         v
+---------------------------------------------------------------------------------+
|                       STAGE 2: PROTOCOL DEMULTIPLEXING                          |
|                                                                                 |
|         +------------------------------+-------------------------------+        |
|         | EtherType == 0x0806 (ARP)    | EtherType == 0x0800 (IPv4)    |        |
|         +--------------+---------------+---------------+---------------+        |
+------------------------|-------------------------------|------------------------+
                         |                               |
                         v                               v
+------------------------------------+   +----------------------------------------+
|          STAGE 3A: ARP PATH        |   |         STAGE 3B: IPv4 PATH            |
| 1. Parse RFC 826 ARP Payload       |   | 1. Validate Version == 4 & IHL >= 5    |
| 2. Opcode == REQUEST:              |   | 2. Validate Total Length <= Frame      |
|    - Update ARP Cache (Sender)     |   | 3. Verify RFC 1071 Header Checksum     |
|    - Target == Router IP ?         |   | 4. Dst == Router IP ?                  |
|      * Generate ARP Reply          |   |    -> Local Delivery Termination       |
| 3. Opcode == REPLY:                |   | 5. TTL Validation:                     |
|    - Update ARP Cache (Sender)     |   |    - TTL <= 1 ? -> [DROP: Expired]     |
|    - Dequeue Pending Packets       |   | 6. LPM Routing Lookup -> Next-Hop IP   |
|    - Rewrite & Transmit Dequeued   |   +-------------------+--------------------+
+------------------------------------+                       |
                                                             v
                                         +----------------------------------------+
                                         |     STAGE 4: NEIGHBOR RESOLUTION       |
                                         |                                        |
                                         | Query ARP Cache for Next-Hop IP:       |
                                         |                                        |
                                         | [HIT: MAC Found]   [MISS: Not Found]   |
                                         +---------+------------------+-----------+
                                                   |                  |
                         +-------------------------+                  |
                         v                                            v
+------------------------------------+   +----------------------------------------+
|    STAGE 5A: FAST-PATH FORWARD     |   |      STAGE 5B: QUEUE & RESOLVE         |
| 1. Decrement TTL: TTL = TTL - 1    |   | 1. Buffer packet in ARP Pending Queue  |
| 2. RFC 1624 Incremental Checksum   |   |    (Subject to per-IP & global limits) |
| 3. Rewrite L2 Header:              |   | 2. Generate ARP Request Frame for      |
|    - Dst MAC = Next-Hop MAC        |   |    Next-Hop IP                         |
|    - Src MAC = Egress Interface MAC|   | 3. Transmit ARP Request onto wire      |
| 4. Transmit out Egress Interface   |   +----------------------------------------+
+------------------------------------+
```

---

## 2. Fast-Path Header Transformation

Forwarding an IPv4 packet requires modifying Layer 2 and Layer 3 headers in-place with zero memory reallocation:

### 2.1 Layer 3 Header Rewriting
1. **TTL Decrement**: Decrements the 8-bit TTL field at byte offset 8:
   $$\text{TTL}_{\text{new}} = \text{TTL}_{\text{old}} - 1$$
2. **RFC 1624 Incremental Checksum Update**:
   Instead of summing all 20 bytes of the IP header ($O(N)$), the router updates the 16-bit word at offset 8 ($[\text{TTL} \mid \text{Protocol}]$):
   $$m = (\text{TTL}_{\text{old}} \ll 8) \mid \text{Protocol}$$
   $$m' = (\text{TTL}_{\text{new}} \ll 8) \mid \text{Protocol}$$
   $$\text{Sum} = (\sim HC \ \& \ \text{0xFFFF}) + (\sim m \ \& \ \text{0xFFFF}) + (m' \ \& \ \text{0xFFFF})$$
   $$\text{Folded} = (\text{Sum} \gg 16) + (\text{Sum} \ \& \ \text{0xFFFF})$$
   $$HC_{\text{new}} = \sim\text{Folded} \ \& \ \text{0xFFFF}$$

### 2.2 Layer 2 Header Rewriting
- Destination MAC is rewritten to the resolved next-hop MAC.
- Source MAC is rewritten to the hardware MAC address of the egress interface.
- 802.1Q VLAN tags are preserved or encapsulated depending on egress port configuration.

---

## 3. ARP Pending Queue State Machine

When a router receives traffic for an IP address whose MAC address is not yet in the ARP table (neighbor cache miss):
1. The incoming packet cannot be transmitted immediately.
2. Dropping immediately causes severe TCP throughput degradation during cold starts.
3. The forwarder enqueues the packet into `ArpCache::queue_pending_packet()`.
4. **Queue Limits**:
   - `DEFAULT_MAX_QUEUE_PER_IP = 16`: Prevents any single destination IP from dominating queue capacity.
   - `DEFAULT_MAX_TOTAL_QUEUED = 1024`: Bounds total buffer memory to under 2 MB, preventing DoS attacks.
   - `DEFAULT_PENDING_TIMEOUT = 5 seconds`: Automatically discards stale unresolved packets.
5. An ARP Request is broadcasted on the egress subnet.
6. When the target host responds with an ARP Reply:
   - The ARP cache entry transitions to `REACHABLE`.
   - All pending packets for that IP are dequeued, their L2/L3 headers are rewritten, and they are transmitted in FIFO order.

---

## 4. Hardware Telemetry & Counters

The forwarder maintains 64-bit atomic/padded counters (`router_stats_t`) aligned to a cache line:

| Counter Group | Metrics | Description |
| :--- | :--- | :--- |
| **I/O Telemetry** | `rx_packets`, `rx_bytes`, `tx_packets`, `tx_bytes` | Total volume ingress and egress |
| **L2 Counters** | `l2_broadcast_packets`, `l2_vlan_tagged_packets`, `l2_frame_too_short`, `l2_frame_too_long`, `l2_dst_mac_mismatch` | Frame sanity and filtering |
| **L3 Counters** | `l3_ipv4_packets`, `l3_forwarded`, `l3_local_delivered`, `l3_checksum_errors`, `l3_ttl_expired`, `l3_no_route` | IPv4 routing and drop reasons |
| **ARP Telemetry** | `arp_requests_received`, `arp_replies_sent`, `arp_cache_hits`, `arp_cache_misses`, `arp_pending_queued`, `arp_pending_dequeued` | Neighbor discovery performance |
