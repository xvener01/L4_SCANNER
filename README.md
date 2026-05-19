# Project 1 - OMEGA: L4 Scanner
Author: Jakub Venera (xvener01)

# Introduction
A port scanner is a tool designed to analyse network ports and identify their state – whether they are open, closed, or filtered. This implementation, written in C++17 using **libpcap** and **POSIX raw sockets**, supports scanning via both TCP and UDP protocols and handles IPv4 as well as IPv6 addresses. Its main purpose is to give network administrators and developers a simple but effective way to verify the availability of network services on specific ports.

The tool is particularly useful when you need to quickly diagnose connectivity issues, verify firewall configuration, or confirm that server applications are reachable. For example, after deploying a new web server you can use the scanner to check whether port 80 (HTTP) or port 443 (HTTPS) is accessible. Equally, UDP scanning can confirm that a DNS server is listening on port 53.

The design combines the low overhead of UDP with the precision of TCP SYN scanning, making it a versatile solution for different types of network audits.


# Theory

## Transmission Control Protocol (TCP)
TCP is a connection-oriented and reliable transport protocol that guarantees delivery of data in the order it was sent. This is achieved through a three-way handshake (SYN → SYN-ACK → ACK) that establishes a connection between client and server before any data is exchanged. Every segment carries a sequence number and a checksum, enabling error detection and retransmission.

TCP also implements flow control and congestion avoidance mechanisms. These properties make it ideal for applications requiring high reliability – web servers, e-mail services (SMTP, IMAP), SSH, and so on.

For port scanning, the **SYN scan** technique is used: a SYN packet is sent and the response determines port status. A SYN-ACK reply means the port is **open**; an RST reply means it is **closed**; no reply (after a timeout) means it is **filtered**.

## User Datagram Protocol (UDP)
UDP is a connectionless and unreliable protocol that provides no delivery or ordering guarantees. Data is sent without a prior handshake, which minimises latency and overhead. This makes UDP suitable for applications where speed matters more than reliability – video streaming, VoIP, online gaming, DNS, and so on.

UDP port state is inferred from **ICMP responses**. If the target port is closed, the host typically replies with an ICMP *Port Unreachable* message (type 3, code 3 for IPv4; type 1, code 4 for ICMPv6). If no response is received within the timeout, the port is considered **open** (or silently filtered by a firewall). This inherent ambiguity requires more careful interpretation of UDP results compared with TCP.

---

# Architecture and Implementation

## Main Components
The scanner is structured into three logical sections inside `main.cpp`:

- **UDP_SCAN** logic (`scanUDP()`) – opens a libpcap handle on the chosen interface, installs a BPF filter for ICMP/ICMPv6 error messages and any UDP replies, then sends a small probe datagram. A background thread dispatches arriving packets via `udpPacketHandler()`. After the timeout the thread is stopped and the result is read from shared atomic flags.

- **TCP_SCAN** logic (`scanTCP()`) – manually constructs a SYN packet (`buildIPv4SynPacket()`), sends it via a raw `IPPROTO_TCP` socket, and reads incoming packets in a polling loop until a SYN-ACK or RST is received or the timeout expires. When an open port is found, `sendRstPacket()` is called immediately to tear down the half-open connection cleanly.

- **Main / argument parsing** (`main()`) – parses command-line arguments, resolves hostnames via `getaddrinfo()`, iterates over all addresses × ports, and prints results.

## Network Interface and Address Handling
`getInterfaceIPv4()` and `getInterfaceIPv6()` use `getifaddrs()` (POSIX) to look up the address of the chosen interface. This is essential for binding the sending socket and building correct packet headers in multi-homed environments. If no interface is specified, `printActiveInterfaces()` lists all interfaces found by `pcap_findalldevs()`.

## Port Ranges and Timeout
The user may specify ports as individual values (`80`), comma-separated lists (`22,80,443`), or ranges (`1-1024`). `parsePortRanges()` converts any combination into a `std::set<int>`, which automatically removes duplicates. The default timeout is **5000 ms** and can be overridden with `-w`.

---

# Implementation Details

## Packet Construction
SYN packets for IPv4 are built manually byte-by-byte in `buildIPv4SynPacket()`. This includes:
- IPv4 header with randomised identification and a random source port / sequence number.
- TCP header with the SYN flag set and TCP options (MSS 1460, SACK Permitted, Timestamps).
- IP checksum via `calculateIpChecksum()`.
- TCP checksum via `calculateTcpChecksum()` using the RFC 793 pseudo-header (src IP, dst IP, protocol, TCP segment length) — **all fields summed as 16-bit words**.

IPv6 SYN packets are built in `buildIPv6SynPacket()`. The IPv6 header is 40 bytes with the Next Header field correctly placed at **byte 6** (value `0x06` = TCP).

## Capturing Responses
For UDP, libpcap is opened with `pcap_open_live()` and a BPF filter string of the form:

```
(icmp and host <target>) or (udp and host <target> and port <port>)
```

Packet dispatch runs on a `std::thread` using `pcap_dispatch()` in a loop. Shared result flags (`isClosed`, `responseReceived`) are `std::atomic<bool>` to avoid data races between the capture thread and the main thread.

For TCP, a raw socket (`SOCK_RAW / IPPROTO_TCP`) with `IP_HDRINCL` is used for both sending and receiving. `SO_RCVTIMEO` drives the receive timeout; a retry counter allows one re-send before the port is declared filtered.

## Error Handling
All system call failures are reported to `stderr` with a descriptive message. Port range and timeout parse errors exit with code 1. Raw socket and pcap operations require root privileges; a clear message is printed if they fail.

---

# Usage and Examples

```
./ipk-l4-scan [-i interface | --interface interface]
              [--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges]
              {-w timeout}
              [hostname | ip-address]
```

**List active interfaces:**
```
./ipk-l4-scan
./ipk-l4-scan -i
```

**Scan UDP ports 53 and 5353 on a host:**
```
sudo ./ipk-l4-scan -i eth0 -u 53,5353 192.168.1.1
```
Output:
```
192.168.1.1 53 udp closed
192.168.1.1 5353 udp open
```

**Scan TCP ports 22, 80, 443:**
```
sudo ./ipk-l4-scan -i eth0 -t 22,80,443 192.168.1.1
```
Output:
```
192.168.1.1 22 tcp open
192.168.1.1 80 tcp open
192.168.1.1 443 tcp filtered
```

**Scan a range of UDP ports with a custom timeout:**
```
sudo ./ipk-l4-scan -i lo -u 10-15 --wait 2000 localhost
```

**Scan an IPv6 address:**
```
sudo ./ipk-l4-scan -i eth0 -u 53,80 fd00::1
```

---

# Build

Requirements: `g++` (≥ C++17), `libpcap-dev`

```
make
```

Run (root required for raw sockets and libpcap):
```
sudo ./ipk-l4-scan ...
```

Clean:
```
make clean
```

---

# Testing

## Overview
Testing focused on verifying core functionality, IPv4/IPv6 compatibility, argument parsing, and edge cases. Results were compared against **nmap** output and verified with **Wireshark**.

## Test Scenarios

### Basic UDP Port Scan
Target: `localhost`, ports `53,5353`. Port 5353 (mDNS service running) → `open`; port 53 (no DNS server) → `closed`. Results matched `nmap -sU`.

### Basic TCP Port Scan
SYN scan on common ports (22, 80, 443). Open ports returned SYN-ACK → `open`; closed ports returned RST → `closed`; firewalled ports timed out → `filtered`.

### Port Range Parsing
`-u 10-15 localhost` — Wireshark confirmed UDP probes sent to all six ports. Duplicate ports (e.g. `-u 21,30,21,80`) correctly de-duplicated.

### IPv6 Support
`-u 21,30,80 fd00::a00:27ff:fe06:c080` — Wireshark confirmed correct ICMPv6 parsing and proper IPv6 header construction (Next Header = 0x06 at byte 6).

### Timeout Parameter
`-w 500` reduced wait times noticeably for filtered ports, confirming the parameter is respected.

## Conclusion
Testing confirmed:
- Correct port state detection for UDP (open/closed) and TCP (open/closed/filtered)
- IPv4 and IPv6 support for UDP scanning
- Port range and duplicate handling
- Informative error messages for invalid input

---

# Known Issues / Limitations

## Root Privileges Required
Raw socket operations and libpcap both require `CAP_NET_RAW`. Always run with `sudo`.

## IPv6 TCP Scanning
TCP SYN scanning currently uses IPv4 only. IPv6 TCP targets will fail to get an interface address and return early.

## UDP Ambiguity
UDP scanning cannot distinguish between a truly open port and a silently filtered one — both produce no ICMP response. This is an inherent limitation of UDP-based scanning (shared with tools like nmap).

---

# Bibliography

- RFC 793: *Transmission Control Protocol*, IETF, 1981.
- RFC 791: *Internet Protocol*, IETF, 1981.
- RFC 768: *User Datagram Protocol*, IETF, 1980.
- RFC 4443: *Internet Control Message Protocol (ICMPv6)*, IETF, 2006.
- [Nmap: The Art of Port Scanning](https://nmap.org/nmap_doc.html)
- [TCP SYN (Stealth) Scan](https://nmap.org/book/synscan.html)
- [Port scanner – Wikipedia](https://en.wikipedia.org/wiki/Port_scanner)
- [libpcap API documentation](https://www.tcpdump.org/manpages/pcap.3pcap.html)
