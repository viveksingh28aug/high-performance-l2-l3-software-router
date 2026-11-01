# Performance Benchmarks & Systems Analysis

This document reports benchmark results and systems performance analysis for the High-Performance L2/L3 Software Router on Linux. All benchmarks utilize the monotonic clock (`std::chrono::steady_clock`) and evaluate both raw LPM trie lookups and end-to-end packet processing pipeline throughput.

---

## 1. Benchmark Environment

- **Operating System**: Ubuntu Linux (Kernel 7.0.0-38-generic x86_64)
- **Compiler**: GCC 15.2.0 (`-O3 -march=native -std=c++17`)
- **Compilation Mode**: Release (Sanitizers disabled for pure hardware measurement)
- **Clock Source**: Monotonic Steady Clock (`CLOCK_MONOTONIC_RAW`)
- **Memory Management**: Fixed cache-aligned descriptor ring, zero fast-path heap allocations

---

## 2. Benchmark Results

The following table reflects the audited benchmark results:

| Benchmark Scenario | Active Routes | Query Iterations | Execution Time (ms) | Throughput (Mpps) | Latency (ns/lookup) |
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
| **1M Lookups (/16 routes)** | 10,000 | 1,000,000 | 45.50 ms | **21.98 Mpps** | **45.5 ns** |
| **1M Lookups (/24 routes)** | 10,000 | 1,000,000 | 54.50 ms | **18.35 Mpps** | **54.5 ns** |
| **1M Lookups (/32 routes)** | 10,000 | 1,000,000 | 59.02 ms | **16.94 Mpps** | **59.0 ns** |
| **Full Pipeline Fast-Path (100k pkts)** | 1 | 100,000 | 11.29 ms | **8.86 Mpps** | **112.9 ns** |
| **Full Pipeline Fast-Path (1M pkts)** | 1 | 1,000,000 | 112.87 ms | **8.86 Mpps** | **112.9 ns** |

---

## 3. Systems & Architectural Analysis

### 3.1 Cache Locality vs. Table Size
- **Small Tables (100 to 1,000 routes)**:
  - The working set of trie nodes fits entirely within the CPU's L1/L2 data cache ($32\text{ KB} - 512\text{ KB}$).
  - Throughput achieves **41.37 to 45.02 Mpps** (~22 to 24 nanoseconds per lookup).
- **Medium Tables (10,000 routes)**:
  - Trie nodes span L2 and L3 shared cache.
  - Throughput stabilizes at **17.31 to 20.31 Mpps** (~49 to 58 ns per lookup).
- **Large Tables (50,000 routes)**:
  - Working set size exceeds CPU L2 cache, inducing occasional L3/DRAM line fills.
  - Throughput delivers **6.83 to 8.95 Mpps** (112 to 146 ns per lookup).

### 3.2 Impact of Prefix Length
- **/8 Prefixes**: Traversal terminates at depth 8. Achieves **102.21 Mpps** (~9.8 ns per lookup).
- **/16 to /32 Prefixes**: Latency scales with prefix depth ($O(W)$), reaching 16.94 to 21.98 Mpps for full /24 and /32 routes.

### 3.3 End-to-End Pipeline Performance
The full forwarding pipeline fast-path performs:
1. Frame boundary and sanity validation.
2. Layer 2 parsing and destination MAC filtering.
3. Layer 3 IPv4 header parsing, version/IHL checks, and length verification.
4. LPM routing table lookup.
5. ARP cache resolution.
6. TTL decrement.
7. RFC 1624 incremental 16-bit checksum recalculation.
8. Layer 2 header rewrite (rewriting source & destination MAC).
9. Egress queue dispatch.

**Measured Pipeline Throughput**: **8.86 Million Packets Per Second** (~112.9 ns per packet) on a single CPU core.

---

## 4. Benchmark Reproduction Commands

```bash
# 1. Configure optimized release build
cmake -B build-bench -DCMAKE_BUILD_TYPE=Release -DENABLE_SANITIZERS=OFF

# 2. Build the dedicated benchmark executable
cmake --build build-bench --target router_benchmark -j$(nproc)

# 3. Execute the benchmark suite
./build-bench/router_benchmark
```
