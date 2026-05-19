// ipk-l4-scan — L4 Port Scanner
// Author: Jakub Venera (xvener01)
// Rewritten from C# (SharpPcap) to C++17 using libpcap + POSIX raw sockets
//
// Bug fixes vs. original C# version:
//   FIX #1 parseTcpResponse()       – checked response src-port instead of dst-port
//   FIX #2 calculateTcpChecksum()   – pseudo-header was summed byte-by-byte; now 16-bit words
//   FIX #3 buildIPv6SynPacket()     – Next Header was written to bytes 4-5 (payload length);
//                                     now correctly placed at byte 6

#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <chrono>
#include <thread>
#include <atomic>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <pcap/pcap.h>

// =====================================================================
// Types
// =====================================================================

enum TcpFlags : uint8_t {
    TCP_NONE = 0,
    TCP_FIN  = 1,
    TCP_SYN  = 2,
    TCP_RST  = 4,
    TCP_PSH  = 8,
    TCP_ACK  = 16,
    TCP_URG  = 32
};

struct TargetAddress {
    std::string ip;
    bool        isIPv6;
};

// Atomic bools: packet callback runs on a separate thread
struct UdpScanState {
    std::atomic<bool> isClosed{false};
    std::atomic<bool> responseReceived{false};
};

// =====================================================================
// Random number generator (seeded once per process)
// =====================================================================

static std::mt19937& getRng() {
    static std::mt19937 rng(std::random_device{}());
    return rng;
}

// =====================================================================
// Interface address helpers
// =====================================================================

static bool getInterfaceIPv4(const std::string& ifname, struct in_addr& addr) {
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return false;
    bool found = false;
    for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_name && ifname == ifa->ifa_name &&
            ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            addr  = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr;
            found = true;
            break;
        }
    }
    freeifaddrs(ifap);
    return found;
}

static bool getInterfaceIPv6(const std::string& ifname, struct in6_addr& addr) {
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return false;
    bool found = false;
    for (struct ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_name && ifname == ifa->ifa_name &&
            ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
            addr  = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
            found = true;
            break;
        }
    }
    freeifaddrs(ifap);
    return found;
}

// =====================================================================
// Interface listing / help / port parsing
// =====================================================================

static void printActiveInterfaces() {
    pcap_if_t* alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return;
    }
    std::cout << "Active interfaces:\n";
    for (pcap_if_t* d = alldevs; d; d = d->next)
        std::cout << "- " << d->name << " ("
                  << (d->description ? d->description : "no description") << ")\n";
    pcap_freealldevs(alldevs);
}

static void printHelp() {
    std::cout <<
        "Usage: ./ipk-l4-scan [-i interface | --interface interface]\n"
        "                     [--pu port-ranges | --pt port-ranges |\n"
        "                      -u  port-ranges  | -t  port-ranges ]\n"
        "                     {-w timeout} [hostname | ip-address]\n\n"
        "Parameters:\n"
        "  -h / --help        Print this help and exit\n"
        "  -i / --interface   Network interface to use; omit value to list interfaces\n"
        "  -t / --pt          TCP port(s) to scan  (e.g. 22 | 1-1024 | 22,80,443)\n"
        "  -u / --pu          UDP port(s) to scan  (e.g. 53 | 1-1024 | 53,5353)\n"
        "  -w / --wait        Response timeout in ms (default: 5000)\n"
        "  hostname / IP      Target: IPv4/IPv6 address or hostname\n";
}

static std::set<int> parsePortRanges(const std::string& input) {
    std::set<int>  ports;
    std::stringstream ss(input);
    std::string    part;
    while (std::getline(ss, part, ',')) {
        size_t dashPos = part.find('-');
        if (dashPos != std::string::npos) {
            try {
                int start = std::stoi(part.substr(0, dashPos));
                int end   = std::stoi(part.substr(dashPos + 1));
                for (int p = start; p <= end; p++) ports.insert(p);
            } catch (...) {
                std::cerr << "Error: Invalid port range.\n";
                exit(1);
            }
        } else {
            try   { ports.insert(std::stoi(part)); }
            catch (...) {
                std::cerr << "Error: Invalid port range.\n";
                exit(1);
            }
        }
    }
    return ports;
}

// =====================================================================
// Checksum helpers
// =====================================================================

static uint16_t calculateIpChecksum(const uint8_t* header) {
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2)
        sum += (uint32_t)((header[i] << 8) + header[i + 1]);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// FIX #2: pseudo-header summed as 16-bit words (RFC 793), not individual bytes
static uint16_t calculateTcpChecksum(const uint8_t* packet, int packetLen,
                                      const struct in_addr& srcIp,
                                      const struct in_addr& dstIp) {
    uint8_t pseudoHeader[12] = {};
    memcpy(pseudoHeader,     &srcIp.s_addr, 4);
    memcpy(pseudoHeader + 4, &dstIp.s_addr, 4);
    pseudoHeader[9]   = 0x06;  // TCP protocol number
    uint16_t tcpLen   = htons((uint16_t)(packetLen - 20));
    memcpy(pseudoHeader + 10, &tcpLen, 2);

    uint32_t sum = 0;
    for (int i = 0; i < 12; i += 2)                         // FIX: 16-bit word iteration
        sum += (uint32_t)((pseudoHeader[i] << 8) + pseudoHeader[i + 1]);

    for (int i = 20; i < packetLen; i += 2) {
        if (i + 1 < packetLen)
            sum += (uint32_t)((packet[i] << 8) + packet[i + 1]);
        else
            sum += packet[i];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// FIX #2 applied to IPv6 variant as well
static void calculateTcpChecksumIPv6(uint8_t* packet, int packetLen,
                                      const struct in6_addr& srcIp,
                                      const struct in6_addr& dstIp) {
    uint8_t pseudoHeader[40] = {};
    memcpy(pseudoHeader,      &srcIp, 16);
    memcpy(pseudoHeader + 16, &dstIp, 16);
    uint32_t tcpLenBE = htonl(20);
    memcpy(pseudoHeader + 36, &tcpLenBE, 4);
    pseudoHeader[39] = 0x06;  // TCP

    uint32_t sum = 0;
    for (int i = 0; i < 40; i += 2)                         // FIX: 16-bit word iteration
        sum += (uint32_t)((pseudoHeader[i] << 8) + pseudoHeader[i + 1]);

    for (int i = 40; i < packetLen; i += 2) {
        if (i + 1 < packetLen)
            sum += (uint32_t)((packet[i] << 8) + packet[i + 1]);
        else
            sum += packet[i];
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t checksum = (uint16_t)~sum;
    memcpy(packet + 50, &checksum, 2);
}

// =====================================================================
// Packet builders
// =====================================================================

static std::vector<uint8_t> buildIPv4SynPacket(const struct in_addr& srcIp,
                                                const struct in_addr& dstIp,
                                                int dstPort,
                                                uint16_t& srcPort,
                                                uint32_t& seqNumber) {
    std::vector<uint8_t> packet(60, 0);
    auto& rng = getRng();
    srcPort   = (uint16_t)std::uniform_int_distribution<int>(1024, 0xFFFE)(rng);
    seqNumber = std::uniform_int_distribution<uint32_t>()(rng);

    // IPv4 header
    packet[0] = 0x45;                                        // Version=4, IHL=5
    uint16_t totalLen = htons(60);
    memcpy(packet.data() + 2, &totalLen, 2);
    uint16_t id = (uint16_t)std::uniform_int_distribution<int>(0, 0xFFFF)(rng);
    memcpy(packet.data() + 4, &id, 2);
    packet[6] = 0x40;                                        // Don't Fragment
    packet[8] = 0x40;                                        // TTL = 64
    packet[9] = 0x06;                                        // Protocol = TCP
    memcpy(packet.data() + 12, &srcIp.s_addr, 4);
    memcpy(packet.data() + 16, &dstIp.s_addr, 4);

    // TCP header
    uint16_t srcPortNet = htons(srcPort);
    uint16_t dstPortNet = htons((uint16_t)dstPort);
    memcpy(packet.data() + 20, &srcPortNet, 2);
    memcpy(packet.data() + 22, &dstPortNet, 2);
    uint32_t seqNet = htonl(seqNumber);
    memcpy(packet.data() + 24, &seqNet, 4);
    packet[32] = 0xA0;                                       // Data Offset = 10 (40 bytes)
    packet[33] = 0x02;                                       // SYN flag
    uint16_t win = htons(65495);
    memcpy(packet.data() + 34, &win, 2);

    // TCP Options: MSS + SACK-permitted + Timestamps
    int off = 40;
    packet[off++] = 0x02; packet[off++] = 0x04;             // MSS kind + length
    uint16_t mss = htons(1460);
    memcpy(packet.data() + off, &mss, 2); off += 2;
    packet[off++] = 0x04; packet[off++] = 0x02;             // SACK Permitted
    packet[off++] = 0x08; packet[off++] = 0x0A;             // Timestamps kind + length
    auto ms = (uint32_t)(std::chrono::steady_clock::now().time_since_epoch().count() / 1'000'000);
    uint32_t tsval = htonl(ms);
    memcpy(packet.data() + off, &tsval, 4); off += 4;
    uint32_t tsecr = 0;
    memcpy(packet.data() + off, &tsecr, 4);

    // Checksums
    uint16_t ipCk = calculateIpChecksum(packet.data());
    memcpy(packet.data() + 10, &ipCk, 2);
    uint16_t tcpCk = calculateTcpChecksum(packet.data(), 60, srcIp, dstIp);
    memcpy(packet.data() + 36, &tcpCk, 2);

    return packet;
}

// FIX #3: Next Header is now written to byte 6 (correct IPv6 header layout)
static std::vector<uint8_t> buildIPv6SynPacket(const struct in6_addr& srcIp,
                                                const struct in6_addr& dstIp,
                                                int dstPort,
                                                uint16_t& srcPort) {
    std::vector<uint8_t> packet(60, 0);
    srcPort = (uint16_t)std::uniform_int_distribution<int>(1024, 65535)(getRng());

    // IPv6 header (40 bytes)
    packet[0] = 0x60;                                        // Version = 6
    uint16_t payloadLen = htons(20);                         // TCP header only
    memcpy(packet.data() + 4, &payloadLen, 2);               // bytes 4-5: Payload Length
    packet[6] = 0x06;   // FIX: Next Header = TCP at byte 6 (was incorrectly at bytes 4-5)
    packet[7] = 0x40;                                        // Hop Limit = 64
    memcpy(packet.data() + 8,  &srcIp, 16);
    memcpy(packet.data() + 24, &dstIp, 16);

    // TCP header
    uint16_t srcPortNet = htons(srcPort);
    uint16_t dstPortNet = htons((uint16_t)dstPort);
    memcpy(packet.data() + 40, &srcPortNet, 2);
    memcpy(packet.data() + 42, &dstPortNet, 2);
    packet[49] = 0x02;                                       // SYN flag
    packet[52] = 0x00; packet[53] = 0xFA;                   // Window Size

    calculateTcpChecksumIPv6(packet.data(), 60, srcIp, dstIp);
    return packet;
}

// =====================================================================
// TCP: response parser
// =====================================================================

// FIX #1: check DESTINATION port of the response (= our source port),
//         not SOURCE port (= server port, which is what the old code checked).
//         The incoming response has: src=server_port, dst=our_random_srcPort.
static uint8_t parseTcpResponse(const uint8_t* data, uint16_t expectedSrcPort,
                                 uint32_t expectedAckNumber) {
    int ipHeaderLen = (data[0] & 0x0F) * 4;
    int tcpStart    = ipHeaderLen;

    // FIX: bytes [tcpStart+2 .. tcpStart+3] = destination port of response = our src port
    uint16_t dstPort = ntohs(*reinterpret_cast<const uint16_t*>(data + tcpStart + 2));
    if (dstPort != expectedSrcPort) return TCP_NONE;

    uint32_t ackNumber = ntohl(*reinterpret_cast<const uint32_t*>(data + tcpStart + 8));
    if (ackNumber != expectedAckNumber) return TCP_NONE;

    return data[tcpStart + 13];  // TCP flags byte
}

// =====================================================================
// TCP: RST sender (cleanly resets half-open connections from SYN scan)
// =====================================================================

static void sendRstPacket(const struct in_addr& srcIp, const struct in_addr& dstIp,
                           int dstPort, const uint8_t* response) {
    int ipHeaderLen = (response[0] & 0x0F) * 4;
    int tcpStart    = ipHeaderLen;
    uint32_t ackNumber = ntohl(*reinterpret_cast<const uint32_t*>(response + tcpStart + 8));

    std::vector<uint8_t> rstPacket(40, 0);
    rstPacket[0] = 0x45;
    uint16_t totalLen = htons(40);
    memcpy(rstPacket.data() + 2, &totalLen, 2);
    uint16_t id = (uint16_t)std::uniform_int_distribution<int>(0, 0xFFFF)(getRng());
    memcpy(rstPacket.data() + 4, &id, 2);
    rstPacket[6] = 0x40; rstPacket[8] = 0x40; rstPacket[9] = 0x06;
    // Swapped: we reply from dstIp back to srcIp
    memcpy(rstPacket.data() + 12, &dstIp.s_addr, 4);
    memcpy(rstPacket.data() + 16, &srcIp.s_addr, 4);

    uint16_t rSrcPort = ntohs(*reinterpret_cast<const uint16_t*>(response + tcpStart + 2));
    uint16_t rDstPort = ntohs(*reinterpret_cast<const uint16_t*>(response + tcpStart));
    uint16_t sp = htons(rSrcPort), dp = htons(rDstPort);
    memcpy(rstPacket.data() + 20, &sp, 2);
    memcpy(rstPacket.data() + 22, &dp, 2);
    uint32_t ackNet = htonl(ackNumber);
    memcpy(rstPacket.data() + 24, &ackNet, 4);
    rstPacket[33] = 0x14;  // RST + ACK

    uint16_t ipCk  = calculateIpChecksum(rstPacket.data());
    memcpy(rstPacket.data() + 10, &ipCk, 2);
    uint16_t tcpCk = calculateTcpChecksum(rstPacket.data(), 40, dstIp, srcIp);
    memcpy(rstPacket.data() + 36, &tcpCk, 2);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        struct sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_addr   = dstIp;
        dst.sin_port   = htons((uint16_t)dstPort);
        sendto(sock, rstPacket.data(), rstPacket.size(), 0,
               reinterpret_cast<struct sockaddr*>(&dst), sizeof(dst));
        close(sock);
    }
}

// =====================================================================
// TCP: full SYN scan
// =====================================================================

static void scanTCP(const std::string& ifname, const std::string& targetIPStr,
                    int port, int timeout) {
    struct in_addr srcIPv4{};
    if (!getInterfaceIPv4(ifname, srcIPv4)) {
        std::cerr << "Error: Cannot get IPv4 address for interface " << ifname << ".\n";
        return;
    }

    struct in_addr dstIPv4{};
    inet_pton(AF_INET, targetIPStr.c_str(), &dstIPv4);

    uint16_t srcPort;
    uint32_t seqNumber;
    std::vector<uint8_t> synPacket =
        buildIPv4SynPacket(srcIPv4, dstIPv4, port, srcPort, seqNumber);

    bool isClosed = false, isOpen = false;
    int  retries  = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        std::cerr << "Error: Failed to create raw socket (run as root).\n";
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct timeval tv{};
    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr   = srcIPv4;
    bind(sock, reinterpret_cast<struct sockaddr*>(&bindAddr), sizeof(bindAddr));

    struct sockaddr_in dstAddr{};
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_addr   = dstIPv4;
    dstAddr.sin_port   = htons((uint16_t)port);

    sendto(sock, synPacket.data(), synPacket.size(), 0,
           reinterpret_cast<struct sockaddr*>(&dstAddr), sizeof(dstAddr));

    uint8_t buffer[1024];
    auto    start = std::chrono::steady_clock::now();

    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - start).count() < timeout) {
        int received = (int)recv(sock, buffer, sizeof(buffer), 0);
        if (received > 0) {
            uint8_t flags = parseTcpResponse(buffer, srcPort, seqNumber + 1);
            if (flags & TCP_RST) {
                isClosed = true;
                break;
            } else if ((flags & TCP_SYN) && (flags & TCP_ACK)) {
                isOpen = true;
                sendRstPacket(srcIPv4, dstIPv4, port, buffer);  // clean up half-open
                break;
            }
        } else {
            // Receive timed out: retry once then give up (filtered)
            if (retries > 0) {
                sendto(sock, synPacket.data(), synPacket.size(), 0,
                       reinterpret_cast<struct sockaddr*>(&dstAddr), sizeof(dstAddr));
                retries--;
                start = std::chrono::steady_clock::now();
            } else {
                break;
            }
        }
    }
    close(sock);

    std::string status = isOpen ? "open" : (isClosed ? "closed" : "filtered");
    std::cout << targetIPStr << " " << port << " tcp " << status << "\n";
}

// =====================================================================
// UDP: libpcap packet callback
// =====================================================================

static void udpPacketHandler(u_char* userData, const struct pcap_pkthdr* header,
                              const u_char* packet) {
    auto* state = reinterpret_cast<UdpScanState*>(userData);
    const int ETH_HEADER_LEN = 14;
    if (header->caplen < (uint32_t)(ETH_HEADER_LEN + 20)) return;

    const u_char* ipStart   = packet + ETH_HEADER_LEN;
    uint8_t       ipVersion = (ipStart[0] >> 4);

    if (ipVersion == 4) {
        int     ipHeaderLen = (ipStart[0] & 0x0F) * 4;
        if (header->caplen < (uint32_t)(ETH_HEADER_LEN + ipHeaderLen + 2)) return;
        uint8_t protocol    = ipStart[9];
        if (protocol == 1) {  // ICMP
            uint8_t icmpType = ipStart[ipHeaderLen];
            uint8_t icmpCode = ipStart[ipHeaderLen + 1];
            if (icmpType == 3 && icmpCode == 3)  // Port Unreachable
                state->isClosed = true;
            state->responseReceived = true;
        }
    } else if (ipVersion == 6) {
        const int ipHeaderLen = 40;
        uint8_t   nextHeader  = ipStart[6];
        if (nextHeader == 58) {  // ICMPv6
            int icmpv6Offset = ipHeaderLen;
            if (header->caplen >= (uint32_t)(ETH_HEADER_LEN + icmpv6Offset + 4)) {
                uint8_t icmpType = ipStart[icmpv6Offset];
                uint8_t icmpCode = ipStart[icmpv6Offset + 1];
                if (icmpType == 1 && icmpCode == 4) {  // Destination Unreachable / Port Unreachable
                    state->isClosed      = true;
                    state->responseReceived = true;
                }
            }
        }
    }
}

// =====================================================================
// UDP: full scan
// Returns true  → port closed (or any ICMP response received)
// Returns false → port open / filtered (no response in timeout)
// =====================================================================

static bool scanUDP(const std::string& ifname, const std::string& targetIPStr,
                    bool isIPv6, int port, int timeout) {
    struct in_addr  srcIPv4{};
    struct in6_addr srcIPv6{};

    if (isIPv6) {
        if (!getInterfaceIPv6(ifname, srcIPv6)) {
            std::cerr << "Error: Cannot get IPv6 address for interface " << ifname << ".\n";
            return true;
        }
    } else {
        if (!getInterfaceIPv4(ifname, srcIPv4)) {
            std::cerr << "Error: Cannot get IPv4 address for interface " << ifname << ".\n";
            return true;
        }
    }

    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(ifname.c_str(), 65535, 0, 100, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        return true;
    }

    std::string icmpProto = isIPv6 ? "icmp6" : "icmp";
    std::string filterStr = "(" + icmpProto + " and host " + targetIPStr +
                            ") or (udp and host " + targetIPStr +
                            " and port " + std::to_string(port) + ")";

    struct bpf_program fp{};
    if (pcap_compile(handle, &fp, filterStr.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        return true;
    }
    pcap_freecode(&fp);

    UdpScanState      state{};
    std::atomic<bool> stopCapture{false};

    // Background capture thread — mirrors SharpPcap's StartCapture()
    std::thread captureThread([&]() {
        while (!stopCapture.load())
            pcap_dispatch(handle, -1, udpPacketHandler,
                          reinterpret_cast<u_char*>(&state));
    });

    // Send UDP probe
    int family  = isIPv6 ? AF_INET6 : AF_INET;
    int udpSock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock >= 0) {
        const char* payload = "Test UDP packet";
        if (isIPv6) {
            struct sockaddr_in6 bindAddr{}, dstAddr{};
            bindAddr.sin6_family = AF_INET6;
            bindAddr.sin6_addr   = srcIPv6;
            bind(udpSock, reinterpret_cast<struct sockaddr*>(&bindAddr), sizeof(bindAddr));
            dstAddr.sin6_family = AF_INET6;
            inet_pton(AF_INET6, targetIPStr.c_str(), &dstAddr.sin6_addr);
            dstAddr.sin6_port = htons((uint16_t)port);
            sendto(udpSock, payload, strlen(payload), 0,
                   reinterpret_cast<struct sockaddr*>(&dstAddr), sizeof(dstAddr));
        } else {
            struct sockaddr_in bindAddr{}, dstAddr{};
            bindAddr.sin_family = AF_INET;
            bindAddr.sin_addr   = srcIPv4;
            bind(udpSock, reinterpret_cast<struct sockaddr*>(&bindAddr), sizeof(bindAddr));
            dstAddr.sin_family = AF_INET;
            inet_pton(AF_INET, targetIPStr.c_str(), &dstAddr.sin_addr);
            dstAddr.sin_port = htons((uint16_t)port);
            sendto(udpSock, payload, strlen(payload), 0,
                   reinterpret_cast<struct sockaddr*>(&dstAddr), sizeof(dstAddr));
        }
        close(udpSock);
    }

    // Wait for responses (mirrors Thread.Sleep(timeout))
    std::this_thread::sleep_for(std::chrono::milliseconds(timeout));

    stopCapture = true;
    pcap_breakloop(handle);
    captureThread.join();
    pcap_close(handle);

    return state.responseReceived.load() || state.isClosed.load();
}

// =====================================================================
// Main
// =====================================================================

int main(int argc, char* argv[]) {
    if (argc == 1) {
        printActiveInterfaces();
        return 0;
    }

    std::string              interfaceName;
    std::vector<TargetAddress> addresses;
    std::set<int>            tcpPorts, udpPorts;
    int                      timeout = 5000;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printHelp();
            return 0;

        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                interfaceName = argv[++i];
            } else {
                printActiveInterfaces();
                return 0;
            }

        } else if (arg == "-t" || arg == "--pt") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                auto p = parsePortRanges(argv[++i]);
                tcpPorts.insert(p.begin(), p.end());
            }

        } else if (arg == "-u" || arg == "--pu") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                auto p = parsePortRanges(argv[++i]);
                udpPorts.insert(p.begin(), p.end());
            }

        } else if (arg == "-w" || arg == "--wait") {
            if (i + 1 < argc) {
                try   { timeout = std::stoi(argv[++i]); }
                catch (...) {
                    std::cerr << "Error: Timeout must be a number.\n";
                    return 1;
                }
            }

        } else if (arg[0] == '-') {
            std::cerr << "Error: Unknown parameter.\n";
            return 1;

        } else {
            // Resolve hostname / IP address
            struct addrinfo hints{}, *res = nullptr;
            hints.ai_family   = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(arg.c_str(), nullptr, &hints, &res) != 0) {
                std::cerr << "Error: Invalid address or hostname.\n";
                return 1;
            }
            for (struct addrinfo* p = res; p; p = p->ai_next) {
                char ipStr[INET6_ADDRSTRLEN];
                bool isIPv6 = (p->ai_family == AF_INET6);
                if (isIPv6)
                    inet_ntop(AF_INET6,
                              &reinterpret_cast<struct sockaddr_in6*>(p->ai_addr)->sin6_addr,
                              ipStr, sizeof(ipStr));
                else
                    inet_ntop(AF_INET,
                              &reinterpret_cast<struct sockaddr_in*>(p->ai_addr)->sin_addr,
                              ipStr, sizeof(ipStr));
                addresses.push_back({std::string(ipStr), isIPv6});
            }
            freeaddrinfo(res);
        }
    }

    for (const auto& addr : addresses) {
        for (int port : udpPorts) {
            if (interfaceName.empty()) {
                std::cerr << "Error: Interface not specified.\n";
                continue;
            }
            bool isClosed = scanUDP(interfaceName, addr.ip, addr.isIPv6, port, timeout);
            std::cout << addr.ip << " " << port << " udp "
                      << (isClosed ? "closed" : "open") << "\n";
        }
        for (int port : tcpPorts) {
            if (interfaceName.empty()) {
                std::cerr << "Error: Interface not specified.\n";
                continue;
            }
            scanTCP(interfaceName, addr.ip, port, timeout);
        }
    }

    return 0;
}
