#include <pcap.h>
#include <iostream>
#include <winsock.h>
#include <vector>
#include <cstdint>

#include "PacketOperations.h"
#include "./helpers/helper.h"
#include "./helpers/protocol_headers.h"


// Background thread for capture
void PacketOperations::start_capture() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum, i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    // Show devices
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)\n", d->description);
        else printf(" (No description available)\n");
    }

    if (i == 0) {
        printf("No interfaces found!\n");
        return;
    }

    printf("Enter interface number (1-%d): ", i);
    scanf_s("%d", &inum);
    if (inum < 1 || inum > i) {
        printf("Out of range\n");
        return;
    }

    // Select device
    for (d = alldevs, i=0; i < inum-1; d = d->next, i++);
    pcap_t* adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);

    if (!adhandle) {
        fprintf(stderr, "Unable to open adapter %s\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }

    CaptureCtx ctx{};
    ctx.linktype = pcap_datalink(adhandle);
    switch (ctx.linktype) {
        case DLT_EN10MB:   ctx.l2len = 14; break; // Ethernet
        case DLT_NULL:     // Npcap loopback
        case DLT_LOOP:     ctx.l2len = 4;  break;
        case DLT_RAW:      ctx.l2len = 0;  break;
        case DLT_LINUX_SLL:ctx.l2len = 16; break;
        default:
            fprintf(stderr, "Unsupported linktype %d\n", ctx.linktype);
            ctx.l2len = 0;
    }

    // Filter for TCP port 33333
    struct bpf_program fcode;
    char packet_filter[] = "ip and tcp port 33333";
    bpf_u_int32 netmask = 0xffffff;
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0 ||
        pcap_setfilter(adhandle, &fcode) < 0) {
        fprintf(stderr, "Error setting filter\n");
        return;
    }

    printf("Started packet capture...\n");
    pcap_freealldevs(alldevs);

    // Blocking capture loop
    pcap_loop(adhandle, 0, packet_handler, reinterpret_cast<u_char*>(&ctx));

    pcap_close(adhandle);
}


void PacketOperations::packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* pkt) {
    auto* ctx = reinterpret_cast<CaptureCtx*>(user);
    if (header->caplen < ctx->l2len + 20) return; // not enough for IPv4 header

    const u_char* p = pkt + ctx->l2len;

    // If Ethernet and not IPv4, skip
    if (ctx->linktype == DLT_EN10MB) {
        const eth_header* eth = reinterpret_cast<const eth_header*>(pkt);
        if (ntohs(eth->ether_type) != 0x0800) return; // not IPv4
    }

    const ip_header* ip = reinterpret_cast<const ip_header*>(p);
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || header->caplen < ctx->l2len + ihl + 20) return;

    if (ip->protocol != IPPROTO_TCP) return;

    const tcp_header* tcp = reinterpret_cast<const tcp_header*>(p + ihl);
    int tcphdrlen = ((tcp->data_offset >> 4) & 0x0F) * 4;; 

    //Computing the payload
    int ip_total_len = ntohs(ip->tot_len);
    int payload_len = ip_total_len - (ihl + tcphdrlen);
    const unsigned char* payload = p + ihl + tcphdrlen; 

    char src[16], dst[16];
    _snprintf_s(src, _TRUNCATE, "%u.%u.%u.%u", ip->saddr[0], ip->saddr[1], ip->saddr[2], ip->saddr[3]);
    _snprintf_s(dst, _TRUNCATE, "%u.%u.%u.%u", ip->daddr[0], ip->daddr[1], ip->daddr[2], ip->daddr[3]);

    std::cout << "Source IP Address: " << src << " Source Port: " << ntohs(tcp->source_port) << " --> Destination IP Address: " << dst << " Destination Port: " << ntohs(tcp->dest_port) << std::endl;

    printf("From %s:%u -> %s:%u | Payload length=%d\n",
    src, ntohs(tcp->source_port),
    dst, ntohs(tcp->dest_port),
    payload_len);
}