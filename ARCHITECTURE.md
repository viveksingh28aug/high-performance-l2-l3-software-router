# Software Router Architecture

This document describes the high-performance Layer 2 / Layer 3 software router architecture implemented in C11/C++17 for Linux. The architecture is engineered to model the fundamental packet processing and forwarding principles found in modern routing systems.

> **Architectural Boundary**: This software router is an independent C11/C++17 educational and systems design model illustrating data plane architecture principles (zero-heap buffers, binary trie Longest Prefix Match, RFC 1624 incremental checksum updates, and run-to-completion pipelines). It does not run on proprietary Cisco Silicon One ASIC hardware or execute inside physical TCAMs.

---

## 1. System Overview

The router is designed as a modular, run-to-completion, zero-copy software data plane. It separates the **Data Plane (Forwarding Path)** from the **Control Plane (Routing & Neighbor Management)** while operating with strict determinism and zero dynamic heap allocation per packet.

```
+-----------------------------------------------------------------------------------+
|                                 CONTROL PLANE                                     |
|  +-----------------------------+        +--------------------------------------+  |
|  |   Routing Table / RIB       |        |        ARP Neighbor Cache            |  |
|  |  (Prefix, Next-Hop, Metric) |        |    (IP -> MAC, State, Timers)        |  |
|  +--------------+--------------+        +-------------------+------------------+  |
+-----------------|-------------------------------------------|---------------------+
                  | FIB Compilation                           | Neighbor Updates
                  v                                           v
+-----------------------------------------------------------------------------------+
|                                  DATA PLANE                                       |
|                                                                                   |
|  +--------------------+        +--------------------+        +-----------------+  |
|  | Packet Ingress     | -----> | Parser & Validation| -----> | LPM FIB Engine  |  |
|  | (AF_PACKET/Offline)|        | (Ethernet, 802.1Q) |        | (Binary Trie)   |  |
|  +--------------------+        +--------------------+        +--------+--------+  |
|                                                                       |           |
|                                                                       v           |
|  +--------------------+        +--------------------+        +-----------------+  |
|  | Packet Egress      | <----- | Header Rewriter    | <----- | Neighbor Lookup |  |
|  | (AF_PACKET/Offline)|        | (TTL, RFC1624, L2) |        | & Pending Queue |  |
|  +--------------------+        +--------------------+        +-----------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Architectural Pillars

### 2.1 Zero-Heap Fast Path
In high-throughput packet processing, allocating heap memory (`malloc`, `new`, `std::make_shared`) on a per-packet basis induces severe latency spikes, memory fragmentation, and cache pollution.
- All packet descriptors (`packet_buffer_t`) use fixed pre-allocated internal buffers (`uint8_t data[MAX_PACKET_SIZE]`) aligned to **64-byte cache line boundaries** (`alignas(64)`).
- Packet metadata (ingress interface ID, egress interface ID, byte length, timestamps) is colocated within the descriptor.

### 2.2 Memory Alignment & Strict Aliasing Safety
Network packets arrive on arbitrary byte boundaries over the wire:
- A standard Ethernet header is 14 bytes, placing the succeeding IPv4 header at byte offset 14 (not a multiple of 4).
- Direct pointer casting (`reinterpret_cast<const iphdr*>(buf + 14)`) triggers unaligned memory access penalties or undefined behavior (UB) on ARM/MIPS and strict-aliasing violations on modern compilers.
- Our data plane uses safe byte-level memory copies (`std::memcpy`) and packed wire structures (`#pragma pack(push, 1)`), which optimizing compilers (GCC/Clang) lower into single vector or unaligned scalar instructions without triggering undefined behavior.

### 2.3 Incremental RFC 1624 Checksum Updates
Recomputing the RFC 1071 Internet Checksum across the entire IPv4 header (20 to 60 bytes) for every forwarded packet burns significant CPU memory bandwidth.
- When decrementing the TTL by 1, the software router uses **RFC 1624 Algorithm 3** to update the 16-bit checksum in $O(1)$ constant time:
  $$HC' = \sim(\sim HC + \sim m + m')$$
- As verified in unit tests, this incremental arithmetic produces the exact bit-for-bit result as a full RFC 1071 recomputation across 100% of tested inputs.

---

## 3. Subsystem Breakdown

### 3.1 Parser Subsystem (`src/parser/`)
- **Ethernet & VLAN Parser**:
  - Validates frame length boundaries: minimum 14 bytes, maximum jumbo 9022 bytes.
  - Supports untagged Ethernet II (`sizeof == 14`), single IEEE 802.1Q tagged (`TPID == 0x8100`), and double-tagged IEEE 802.1ad Q-in-Q frames (`TPID == 0x88A8` outer + `0x8100` inner).
  - Extracts VLAN ID (12 bits), Priority Code Point (PCP, 3 bits), and Drop Eligible Indicator (DEI, 1 bit).
  - Determines inner EtherType and precise byte offset to the L3 payload.
- **IPv4 Parser**:
  - Validates IPv4 version (`version == 4`).
  - Validates Internet Header Length (`IHL >= 5`, minimum 20 bytes).
  - Validates Total Length against frame buffer boundaries.
  - Verifies RFC 1071 header checksum.
  - Evaluates fragmentation state (`DF`, `MF`, `Fragment Offset`).

### 3.2 Routing & LPM Subsystem (`src/routing/`)
- **Binary Trie Forwarding Engine (`LpmTrie`)**:
  - Implements Longest Prefix Match (LPM) over 32-bit IPv4 address space.
  - Bounded worst-case lookup depth of 32 bit decisions.
  - Supports route insertion, route deletion, overlapping prefixes, and default route (`0.0.0.0/0`).
  - Automatic branch pruning upon route deletion to eliminate memory leaks and keep tree depth minimal.
- **Routing Table (`RoutingTable`)**:
  - High-level FIB interface managing prefix lengths, subnet masks, next-hop IPs, egress interfaces, and route metrics.

### 3.3 ARP & Neighbor Management (`src/arp/`)
- **ARP Engine (`ArpCache`)**:
  - RFC 826 ARP Request and Reply generation and parsing.
  - Dynamic state machine: `REACHABLE`, `STALE`, `EXPIRED`, `INCOMPLETE`.
  - Configurable aging and automatic cache sweeps.
- **Pending Packet Queue**:
  - Buffers packets destined for unresolved next-hops.
  - Configurable per-IP queue limit (default 16 packets) and global queue limit (default 1024 packets) to prevent Denial of Service (DoS) attacks.
  - When the corresponding ARP Reply arrives, pending packets are automatically dequeued, rewritten, and transmitted.

### 3.4 Forwarding Pipeline (`src/forwarding/`)
- Orchestrates packet validation, destination MAC verification, ARP handling, IPv4 LPM lookup, ARP resolution, header rewriting, and output interface queuing.
- Updates comprehensive hardware-like performance counters (`router_stats_t`).

### 3.5 Packet I/O (`src/io/`)
- **Offline Mode (`OfflinePacketIO`)**:
  - In-memory simulation and fixture engine for reproducible test suites, CI/CD pipelines, and micro-benchmarking without modifying host networking.
- **Linux AF_PACKET Backend (`AfPacketIO`)**:
  - Raw socket capture (`AF_PACKET, SOCK_RAW, ETH_P_ALL`).
  - Non-blocking socket I/O (`O_NONBLOCK`).
  - Explicit capability checks (`CAP_NET_RAW` / root) and clear operator warnings.
  - Safe lifecycle cleanup on shutdown.

---

## 4. Hardware Comparison & Educational Context

In hardware switching silicon (e.g., Cisco Silicon One, Broadcom Tomahawk):
- **Parser Stage**: Fixed-length header parser pipeline (typically 128 to 256 bytes) implemented in pipelined ASICs.
- **Lookup Engine**: Combination of **TCAM** (Ternary Content Addressable Memory) for $O(1)$ single-cycle LPM lookups and algorithmic SRAM/DRAM trees (e.g., Multi-bit Trie, DIR-24-8, Tree-Bitmap).
- **Packet Buffering**: Shared on-chip buffer memory (packet descriptors and cell rings) without software allocation overhead.
- Our software data plane mirrors these principles on CPU architectures: fixed-size descriptors, cache-aligned data structures, bitwise trie lookups, and bounded memory footprints.

---

## 5. Limitations & Production Considerations

1. **Live AF_PACKET Testing**:
   - The Linux AF_PACKET backend is fully implemented (`AfPacketIO`) with non-blocking sockets (`O_NONBLOCK`), `sockaddr_ll` interface binding, capability validation (`CAP_NET_RAW`), and proper lifecycle cleanup.
   - However, **live packet transmission over physical wire interfaces is dependent on host environment privileges and network configuration**. In standard unprivileged CI/container environments without physical or virtual Ethernet (`veth`) interface pairs and root permissions, live AF_PACKET cannot transmit onto physical media. The project relies on its comprehensive **in-memory offline fixture pipeline (`OfflinePacketIO`)** for verified, deterministic, reproducible testing and benchmarks.
   - To safely test live mode locally, create a virtual Ethernet pair (`veth0` <-> `veth1`) in a Linux network namespace.
2. **IPv4 Options**:
   - Standard 20-byte IPv4 headers are processed in the fast path. Packets with IPv4 options (`IHL > 5`) are validated for length and checksum integrity, but options are forwarded without modification.
3. **Transit Fragmentation**:
   - Fragmentation flags are parsed and exposed; transit packet reassembly is intentionally omitted as reassembly is an end-host L4 responsibility.
4. **Dynamic Routing Daemons**:
   - Exposes a clean C++ FIB manipulation API; does not bundle an integrated BGP/OSPF daemon.
