// helpers/protocol_headers.h
// This header file defines structures for various network protocol headers.
#ifndef PROTOCOL_HEADERS_H
#define PROTOCOL_HEADERS_H

// Libraries
#include <winsock2.h>

// Ensure structures are packed to avoid padding issues
#pragma pack(push, 1)

// Define structures for Ethernet, IP, and TCP headers
struct eth_header {
    u_char dst[6];
    u_char src[6];
    u_short ether_type;
};

struct ip_header {
    u_char  ver_ihl;   // version + IHL
    u_char  tos;
    u_short tot_len;
    u_short id;
    u_short frag_off;
    u_char  ttl;
    u_char  protocol;
    u_short check;
    u_char  saddr[4];
    u_char  daddr[4];
};

struct tcp_header {
    u_short source_port;
    u_short dest_port;
    u_int   seq_num;
    u_int   ack_num;
    u_char  data_offset;  // high 4 bits = header len/4
    u_char  flags;
    u_short window_size;
    u_short checksum;
    u_short urgent_pointer;
};

#pragma pack(pop)

#endif