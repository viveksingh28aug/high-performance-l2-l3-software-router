# High-Performance Layer 2 / Layer 3 Software Router in C11/C++17

[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![C11](https://img.shields.io/badge/C-11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_version))
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Sanitizers](https://img.shields.io/badge/ASan%20%2B%20UBSan-0%20errors-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-37%2F37%20passed-brightgreen.svg)]()
[![Performance](https://img.shields.io/badge/LPM%20Throughput-up%20to%20102%20Mpps-orange.svg)]()

A high-performance Layer 2 / Layer 3 software router engineered in **C11 and C++17 for Linux**. This project is a systems-level architectural study designed to demonstrate core networking and packet processing principles relevant to **Cisco Software Engineer** and **Silicon One** routing/forwarding engineering interviews.

> **Architectural Note**: This software router models the fundamental algorithmic data plane concepts (pipelined header parsing, Longest Prefix Matching, zero-heap packet descriptors, and RFC 1624 incremental checksum updates) on commodity Linux CPUs. It is an independent software implementation and does not claim to run proprietary Cisco Silicon One ASIC microcode or execute directly inside hardware TCAMs.

---

## Key Features

- **Zero-Heap Fast Path**: Packets are processed in-place using 64-byte cache-line-aligned pre-allocated descriptor buffers (`packet_buffer_t`). No heap allocation (`malloc`/`new`) occurs during forwarding.
- **Ethernet II & IEEE 802.1Q/802.1ad Parsing**: Wire-format validation, MAC filtering, single 802.1Q VLAN, and double-tagged Q-in-Q frame parsing.
- **IPv4 Processing & RFC 1624 Incremental Checksum**: Full RFC 1071 verification, safe fragmentation flag evaluation, TTL decrement, and $O(1)$ RFC 1624 incremental checksum update.
- **Longest Prefix Matching (LPM) Binary Trie**: Deterministic $O(W)$ lookup depth ($W = 32$), route insertion, default route (`0.0.0.0/0`), overlapping prefix resolution, and automatic branch pruning on deletion.
- **Dynamic ARP Neighbor Cache**: RFC 826 request/reply handling, state machine (`REACHABLE`, `EXPIRED`), periodic aging sweep, and bounded pending packet queue for unresolved neighbors.
- **Dual I/O Backends**:
  - **Offline Simulation (Default)**: In-memory packet injection and fixture testing without modifying host network traffic.
  - **Linux AF_PACKET**: High-speed live raw socket data plane with non-blocking polling and privilege checks.
- **Exhaustive Testing & Fuzzing**: 37 automated GoogleTest cases, boundary verification, and 5,000-frame fuzzing verified under **AddressSanitizer** and **UndefinedBehaviorSanitizer**.
- **Audited Benchmarks**: High-precision monotonic-clock benchmarks measuring up to **102.21 Mpps** for /8 lookups, **45.02 Mpps** for 1M lookups, and **8.86 Mpps** full-pipeline throughput.

---

## Architectural Overview

```
                                  +---------------------------------------+
                                  |            PACKET INGRESS             |
                                  |   (Offline Fixtures / AF_PACKET)      |
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         LAYER 2 PARSER / FILTER       |
                                  |   Frame bounds, 802.1Q, MAC check     |
                                  +-------------------+-------------------+
                                                      |
                           +--------------------------+--------------------------+
                           |                                                     |
                 EtherType == 0x0806 (ARP)                             EtherType == 0x0800 (IPv4)
                           v                                                     v
          +---------------------------------+                   +---------------------------------+
          |            ARP ENGINE           |                   |           IPv4 ENGINE           |
          | - RFC 826 Request / Reply       |                   | - IHL & Length Validation       |
          | - Dynamic Cache & Aging         |                   | - RFC 1071 Checksum Verify      |
          | - Pending Packet Queue          |                   | - TTL Check (TTL > 1)           |
          +---------------------------------+                   +----------------+----------------+
                                                                                 |
                                                                                 v
                                                                +---------------------------------+
                                                                |         LPM TRIE ENGINE         |
                                                                |   Longest Prefix Match (FIB)    |
                                                                +----------------+----------------+
                                                                                 |
                                                                                 v
                                                                +---------------------------------+
                                                                |        NEIGHBOR RESOLUTION      |
                                                                | - ARP Hit  -> Fast Forward      |
                                                                | - ARP Miss -> Buffer & ARP Req  |
                                                                +----------------+----------------+
                                                                                 |
                                                                                 v
                                                                +---------------------------------+
                                                                |     HEADER REWRITE & EGRESS     |
                                                                | - Decrement TTL                 |
                                                                | - RFC 1624 Checksum Update      |
                                                                | - Rewrite Src & Dst MAC         |
                                                                +---------------------------------+
```

---

## Repository Structure

```
High-Performance L2-L3 Software Router/
├── CMakeLists.txt                 # Unified build configuration
├── README.md                      # Project overview and quick start
├── ARCHITECTURE.md                # Data plane architecture and subsystem design
├── ROUTING_DESIGN.md              # Binary trie LPM, branch pruning, and Silicon One comparison
├── PACKET_FORWARDING.md           # Pipeline stages, header rewriting, and ARP queue state machine
├── TESTING.md                     # Test architecture, ASan/UBSan report, and fuzzing
├── BENCHMARKS.md                  # Audited benchmark measurements and systems performance analysis
├── docs/                          # Detailed architecture documentation mirror
├── include/
│   └── router/
│       ├── types.h                # Fixed descriptor buffers, addresses, telemetry stats
│       ├── checksum.h             # RFC 1071 checksum & RFC 1624 incremental update
│       ├── ethernet.h             # Ethernet II & IEEE 802.1Q/802.1ad parser and rewriter
│       ├── ipv4.h                 # IPv4 header parser, validator, and TTL updater
│       ├── arp.h                  # RFC 826 ARP parser, cache, and pending packet queue
│       ├── lpm_trie.h             # Longest Prefix Match binary trie with branch pruning
│       ├── routing_table.h        # Routing table interface (CIDR, netmask, default route)
│       ├── packet_forwarder.h     # Forwarding engine orchestrating L2/L3 pipeline
│       └── packet_io.h            # Abstract PacketIO, OfflinePacketIO, and Linux AfPacketIO
├── src/
│   ├── core/
│   │   ├── types.cpp              # Address formatting and parsing routines
│   │   └── checksum.cpp           # 16-bit 1's complement arithmetic and RFC 1624
│   ├── parser/
│   │   ├── ethernet.cpp           # L2 boundary validation, VLAN tag stripping/parsing
│   │   └── ipv4.cpp               # L3 parsing, checksum verification, TTL decrement
│   ├── routing/
│   │   ├── lpm_trie.cpp           # Trie traversal, node allocation, and recursive pruning
│   │   └── routing_table.cpp      # FIB management and subnet mask helpers
│   ├── arp/
│   │   └── arp_cache.cpp          # ARP table state machine, pending buffers, frame crafting
│   ├── forwarding/
│   │   └── packet_forwarder.cpp   # Core forwarding pipeline and counter updates
│   ├── io/
│   │   └── packet_io.cpp          # In-memory queues & Linux AF_PACKET raw socket
│   └── main/
│       └── main.cpp               # CLI application, offline simulation, and live runner
├── tests/
│   ├── test_checksum.cpp          # RFC 1071 and RFC 1624 validation
│   ├── test_ethernet.cpp          # L2 and VLAN tag unit tests
│   ├── test_ipv4.cpp              # IPv4 header validation and fragmentation tests
│   ├── test_lpm_trie.cpp          # Trie insertion, lookup, and branch pruning tests
│   ├── test_routing_table.cpp     # CIDR and routing table tests
│   ├── test_arp.cpp               # ARP resolution and pending queue tests
│   ├── test_packet_forwarder.cpp  # End-to-end forwarding integration tests
│   └── test_malformed.cpp         # Boundary conditions and fuzzing
└── benchmarks/
    └── routing_benchmarks.cpp     # Dedicated monotonic-clock performance benchmarks
```

---

## Build Instructions

### Prerequisites
- Ubuntu Linux (or modern Linux distribution)
- GCC / G++ ($\ge 9.0$, tested with GCC 15.2.0)
- CMake ($\ge 3.16$)
- Make or Ninja

### 1. Build with Sanitizers (AddressSanitizer + UndefinedBehaviorSanitizer)
```bash
cmake -B build -DENABLE_SANITIZERS=ON
cmake --build build -j$(nproc)
```

### 2. Build Optimized Release for Benchmarks (`-O3 -march=native`)
```bash
cmake -B build-bench -DCMAKE_BUILD_TYPE=Release -DENABLE_SANITIZERS=OFF
cmake --build build-bench -j$(nproc)
```

---

## Running the Router

### 1. Default Offline Simulation Mode (Safe, Does Not Modify Host Network)
```bash
./build/router_app --offline
```
Runs five comprehensive simulation scenarios:
1. Multi-hop IPv4 packet forwarding with LPM route matching and TTL decrement.
2. TTL expiration dropping (`TTL = 1`).
3. ARP neighbor cache miss, packet buffering in pending queue, and forward on ARP reply.
4. IEEE 802.1Q VLAN tagged frame forwarding.
5. Checksum corruption detection and rejection.

### 2. Live AF_PACKET Mode (Optional, Requires Root)
```bash
sudo ./build/router_app --live --interface eth0
```
Binds a non-blocking `AF_PACKET` raw socket to the specified interface.

---

## Running Tests

Execute the GoogleTest suite containing 37 tests:
```bash
./build/router_tests
```
Or via CTest:
```bash
ctest --test-dir build --output-on-failure
```

**Results**: 37/37 Passed (100% pass rate), 0 ASan memory leaks, 0 UBSan errors.

---

## Audited Benchmark Results

Measured on Ubuntu Linux using `CLOCK_MONOTONIC_RAW`:

| Scenario | Table Size | Queries | Execution Time | Throughput | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **100k Lookups (100 routes)** | 100 | 100,000 | 2.42 ms | **41.37 Mpps** | **24.2 ns** |
| **100k Lookups (1k routes)** | 1,000 | 100,000 | 3.90 ms | **25.62 Mpps** | **39.0 ns** |
| **100k Lookups (10k routes)** | 10,000 | 100,000 | 5.78 ms | **17.31 Mpps** | **57.8 ns** |
| **100k Lookups (50k routes)** | 50,000 | 100,000 | 14.64 ms | **6.83 Mpps** | **146.4 ns** |
| **1M Lookups (100 routes)** | 100 | 1,000,000 | 22.21 ms | **45.02 Mpps** | **22.2 ns** |
| **1M Lookups (1k routes)** | 1,000 | 1,000,000 | 33.08 ms | **30.23 Mpps** | **33.1 ns** |
| **1M Lookups (10k routes)** | 10,000 | 1,000,000 | 49.24 ms | **20.31 Mpps** | **49.2 ns** |
| **1M Lookups (50k routes)** | 50,000 | 1,000,000 | 111.73 ms | **8.95 Mpps** | **111.7 ns** |
| **1M Lookups (/8 routes)** | 10,000 | 1,000,000 | 9.78 ms | **102.21 Mpps** | **9.8 ns** |
| **Full Pipeline Fast-Path** | 1 | 1,000,000 | 112.87 ms | **8.86 Mpps** | **112.9 ns** |

To reproduce benchmarks:
```bash
./build-bench/router_benchmark
```

---

## Limitations & Scope

To maintain engineering transparency, the following design boundaries and operational limitations apply:

1. **Live AF_PACKET Testing**:
   - The `AfPacketIO` backend is fully implemented with non-blocking raw sockets, interface binding (`sockaddr_ll`), and privilege checking (`CAP_NET_RAW`).
   - However, **live wire testing requires an active network interface and root privileges**. In automated CI environments and unprivileged developer sessions, live socket creation fails gracefully with a security warning. All automated regression tests and performance benchmarks are verified via the deterministic `OfflinePacketIO` backend.
   - For safe local live testing, operators should create a pair of virtual Ethernet interfaces (`veth0` <-> `veth1`) inside a network namespace rather than binding to physical network adapters.
2. **IPv4 Options**:
   - Standard IPv4 packets with 20-byte headers (`IHL == 5`) are processed in the fast path. Packets with options (`IHL > 5`) have their lengths and checksums verified, but IP options are forwarded without modification.
3. **IPv4 Fragmentation**:
   - Fragmentation flags (`DF`, `MF`, `Fragment Offset`) are parsed and reported. Consistent with standard transit software routers, packet reassembly is not performed in the transit fast path.
4. **Control Plane Integration**:
   - The router implements the Forwarding Information Base (FIB) and ARP neighbor cache. It exposes a direct C++ programmatic API for route programming rather than bundling an active BGP or OSPF routing daemon.

---

## Documentation Links

- [Architecture Deep Dive](docs/ARCHITECTURE.md)
- [Routing Design & Algorithmic LPM Trie](docs/ROUTING_DESIGN.md)
- [Packet Forwarding Pipeline & Data Plane](docs/PACKET_FORWARDING.md)
- [Testing & Sanitizer Verification Guide](docs/TESTING.md)
- [Performance Benchmarks & Systems Analysis](docs/BENCHMARKS.md)
