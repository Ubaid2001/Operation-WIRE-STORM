#ifndef PACKET_OPERATIONS_H
#define PACKET_OPERATIONS_H

#include <winsock.h>

class PacketOperations {
public:
    PacketOperations() = default;
    ~PacketOperations() = default;

    void start_capture();
    static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt);
    
};

#endif