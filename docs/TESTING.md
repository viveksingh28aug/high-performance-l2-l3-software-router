# Testing & Sanitizer Verification Guide

This document details the test strategy, suite architecture, sanitizer verification results, and reproduction commands for the High-Performance L2/L3 Software Router.

---

## 1. Testing Philosophy & Standards

To meet the engineering standards required for Cisco Software Engineer and Silicon One systems roles, the test framework ensures:
1. **Zero Undefined Behavior**: All structures, memory accesses, and bit shifts are strictly bounded and verified under UBSan.
2. **Zero Memory Leaks & Zero Buffer Overflows**: Clean address sanitizer execution verified through AddressSanitizer (`-fsanitize=address`).
3. **Boundary & Malformed Resilience**: The data plane is fuzzed with truncated, malformed, and corrupted packets to ensure crash-free execution.
4. **Deterministic Correctness**: Automated unit and integration tests run offline without external network or root dependencies.

---

## 2. Test Suite Architecture

The test suite is built on GoogleTest and organized into eight targeted test suites comprising 37 distinct unit and integration tests:

| Test Suite | File | Test Cases | Scope |
| :--- | :--- | :---: | :--- |
| **ChecksumTest** | `tests/test_checksum.cpp` | 3 | RFC 1071 calculation, odd-length byte folding, 1,000-iteration equivalence verification between RFC 1624 incremental update and RFC 1071 full recalculation |
| **EthernetTest** | `tests/test_ethernet.cpp` | 6 | MAC operations, Ethernet II parsing, IEEE 802.1Q single VLAN, IEEE 802.1ad Q-in-Q double VLAN, in-place L2 rewrite, truncated frames |
| **IPv4Test** | `tests/test_ipv4.cpp` | 7 | Header parsing, version/IHL validation, length boundary checks, checksum corruption, TTL decrement, TTL expiration, fragmentation flags |
| **LpmTrieTest** | `tests/test_lpm_trie.cpp` | 4 | Prefix insertion (/0 to /32), overlapping prefix hierarchy, longest match resolution, route deletion with branch pruning, move semantics |
| **RoutingTableTest** | `tests/test_routing_table.cpp` | 3 | CIDR parsing, contiguous netmask to prefix length conversion, non-contiguous mask rejection, default route management, table clear |
| **ArpTest** | `tests/test_arp.cpp` | 6 | RFC 826 request/reply parsing and crafting, hardware/protocol validation, cache aging and sweep, pending queue buffering and flush, queue limits |
| **PacketForwarderTest** | `tests/test_packet_forwarder.cpp` | 5 | Multi-subnet L2/L3 forwarding, TTL decrement & checksum rewrite, ARP miss buffering & reply flush, ARP request answering for router IP, local termination |
| **MalformedTest** | `tests/test_malformed.cpp` | 3 | Null pointer safety, frame boundary checks (lengths 0 to 30), 5,000 randomized corrupted frames fuzzing |

---

## 3. Sanitizer Verification & Actual Test Output

The entire test suite was compiled with `-fsanitize=address,undefined -fno-omit-frame-pointer -g` and executed on Ubuntu Linux.

```bash
$ ./build/router_tests
Running main() from .../gtest_main.cc
[==========] Running 37 tests from 8 test suites.
[----------] Global test environment set-up.
[----------] 3 tests from ChecksumTest
[ RUN      ] ChecksumTest.BasicCalculationAndVerification
[       OK ] ChecksumTest.BasicCalculationAndVerification (0 ms)
[ RUN      ] ChecksumTest.OddByteLength
[       OK ] ChecksumTest.OddByteLength (0 ms)
[ RUN      ] ChecksumTest.IncrementalUpdateVsFullRecalculation
[       OK ] ChecksumTest.IncrementalUpdateVsFullRecalculation (1 ms)
[----------] 3 tests from ChecksumTest (2 ms total)

[----------] 6 tests from EthernetTest
[ RUN      ] EthernetTest.MacAddressOperations
[       OK ] EthernetTest.MacAddressOperations (0 ms)
[ RUN      ] EthernetTest.ParseUntaggedEthernetFrame
[       OK ] EthernetTest.ParseUntaggedEthernetFrame (0 ms)
[ RUN      ] EthernetTest.ParseVlanTaggedFrame
[       OK ] EthernetTest.ParseVlanTaggedFrame (0 ms)
[ RUN      ] EthernetTest.ParseQinQDoubleVlanFrame
[       OK ] EthernetTest.ParseQinQDoubleVlanFrame (0 ms)
[ RUN      ] EthernetTest.RewriteHeaderInPlace
[       OK ] EthernetTest.RewriteHeaderInPlace (0 ms)
[ RUN      ] EthernetTest.TruncatedFrames
[       OK ] EthernetTest.TruncatedFrames (0 ms)
[----------] 6 tests from EthernetTest (0 ms total)

[----------] 7 tests from IPv4Test
[ RUN      ] IPv4Test.AddressParsingAndFormatting
[       OK ] IPv4Test.AddressParsingAndFormatting (0 ms)
[ RUN      ] IPv4Test.ValidHeaderParsing
[       OK ] IPv4Test.ValidHeaderParsing (0 ms)
[ RUN      ] IPv4Test.ChecksumCorruption
[       OK ] IPv4Test.ChecksumCorruption (0 ms)
[ RUN      ] IPv4Test.InvalidVersionAndIhl
[       OK ] IPv4Test.InvalidVersionAndIhl (0 ms)
[ RUN      ] IPv4Test.LengthValidation
[       OK ] IPv4Test.LengthValidation (0 ms)
[ RUN      ] IPv4Test.TtlDecrementAndExpiration
[       OK ] IPv4Test.TtlDecrementAndExpiration (0 ms)
[ RUN      ] IPv4Test.FragmentationParsing
[       OK ] IPv4Test.FragmentationParsing (0 ms)
[----------] 7 tests from IPv4Test (0 ms total)

[----------] 4 tests from LpmTrieTest
[ RUN      ] LpmTrieTest.SingleRouteInsertAndLookup
[       OK ] LpmTrieTest.SingleRouteInsertAndLookup (0 ms)
[ RUN      ] LpmTrieTest.OverlappingPrefixesLongestMatch
[       OK ] LpmTrieTest.OverlappingPrefixesLongestMatch (0 ms)
[ RUN      ] LpmTrieTest.DeletionAndBranchPruning
[       OK ] LpmTrieTest.DeletionAndBranchPruning (0 ms)
[ RUN      ] LpmTrieTest.MoveSemantics
[       OK ] LpmTrieTest.MoveSemantics (0 ms)
[----------] 4 tests from LpmTrieTest (0 ms total)

[----------] 3 tests from RoutingTableTest
[ RUN      ] RoutingTableTest.MaskConversion
[       OK ] RoutingTableTest.MaskConversion (0 ms)
[ RUN      ] RoutingTableTest.AddRouteCidrAndDefault
[       OK ] RoutingTableTest.AddRouteCidrAndDefault (0 ms)
[ RUN      ] RoutingTableTest.GetAllRoutesAndClear
[       OK ] RoutingTableTest.GetAllRoutesAndClear (0 ms)
[----------] 3 tests from RoutingTableTest (0 ms total)

[----------] 6 tests from ArpTest
[ RUN      ] ArpTest.ParseAndCreateArpRequest
[       OK ] ArpTest.ParseAndCreateArpRequest (0 ms)
[ RUN      ] ArpTest.ParseAndCreateArpReply
[       OK ] ArpTest.ParseAndCreateArpReply (0 ms)
[ RUN      ] ArpTest.MalformedArpPackets
[       OK ] ArpTest.MalformedArpPackets (0 ms)
[ RUN      ] ArpTest.CacheResolutionAndExpiration
[       OK ] ArpTest.CacheResolutionAndExpiration (1100 ms)
[ RUN      ] ArpTest.PendingPacketBufferingAndFlush
[       OK ] ArpTest.PendingPacketBufferingAndFlush (0 ms)
[ RUN      ] ArpTest.PendingQueueLimits
[       OK ] ArpTest.PendingQueueLimits (0 ms)
[----------] 6 tests from ArpTest (1101 ms total)

[----------] 5 tests from PacketForwarderTest
[ RUN      ] PacketForwarderTest.SuccessfulForwardingWithPrepopulatedArp
[       OK ] PacketForwarderTest.SuccessfulForwardingWithPrepopulatedArp (0 ms)
[ RUN      ] PacketForwarderTest.TtlExpirationDrop
[       OK ] PacketForwarderTest.TtlExpirationDrop (0 ms)
[ RUN      ] PacketForwarderTest.ArpMissBufferingAndReplyResolution
[       OK ] PacketForwarderTest.ArpMissBufferingAndReplyResolution (0 ms)
[ RUN      ] PacketForwarderTest.RespondToArpRequestForRouterIp
[       OK ] PacketForwarderTest.RespondToArpRequestForRouterIp (0 ms)
[ RUN      ] PacketForwarderTest.LocalDeliveryWhenDstIsRouterIp
[       OK ] PacketForwarderTest.LocalDeliveryWhenDstIsRouterIp (0 ms)
[----------] 5 tests from PacketForwarderTest (3 ms total)

[----------] 3 tests from MalformedTest
[ RUN      ] MalformedTest.NullPointerSafety
[       OK ] MalformedTest.NullPointerSafety (0 ms)
[ RUN      ] MalformedTest.FrameBoundaryConditions
[       OK ] MalformedTest.FrameBoundaryConditions (0 ms)
[ RUN      ] MalformedTest.RandomFuzzingNoCrashes
[       OK ] MalformedTest.RandomFuzzingNoCrashes (230 ms)
[----------] 3 tests from MalformedTest (230 ms total)

[----------] Global test environment tear-down
[==========] 37 tests from 8 test suites ran. (1341 ms total)
[  PASSED  ] 37 tests.
```

### Sanitizer Status:
- **AddressSanitizer**: **0 Errors, 0 Leaks, 0 Use-After-Free, 0 Heap/Stack Out-of-Bounds**.
- **UndefinedBehaviorSanitizer**: **0 Warnings, 0 Unaligned Pointer Dereferences, 0 Integer Overflows**.

---

## 4. Test Reproduction Commands

To reproduce the full test build and execution:

```bash
# 1. Configure with ASan and UBSan
cmake -B build -DENABLE_SANITIZERS=ON

# 2. Compile test targets
cmake --build build -j$(nproc)

# 3. Execute GoogleTest binary directly
./build/router_tests

# 4. Or run via CTest
ctest --test-dir build --output-on-failure
```
