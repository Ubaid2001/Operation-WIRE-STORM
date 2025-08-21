// PacketOperations.h
// This header file defines the PacketOperations class for capturing and processing network packets.
#ifndef PACKET_OPERATIONS_H
#define PACKET_OPERATIONS_H

// Libraries
#include <winsock.h>

// Class definition
class PacketOperations {
public:
    PacketOperations() = default;
    ~PacketOperations() = default;

    void start_capture();
    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt);
    
};

#endif