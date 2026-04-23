#include "packet_parser_core.h"

#include <stdio.h>
#include <string.h>

/* IANA protocol name lookup table */
static const struct {
    uint8_t proto;
    const char *name;
} PROTO_TABLE[] = {
    {1,   "ICMP"},
    {2,   "IGMP"},
    {6,   "TCP"},
    {17,  "UDP"},
    {47,  "GRE"},
    {50,  "ESP"},
    {51,  "AH"},
    {89,  "OSPF"},
    {132, "SCTP"},
    {0,   NULL}
};

static const char *proto_name(uint8_t proto, char *buf, size_t buf_size) {
    int i;

    for (i = 0; PROTO_TABLE[i].name != NULL; i++) {
        if (PROTO_TABLE[i].proto == proto) {
            return PROTO_TABLE[i].name;
        }
    }

    snprintf(buf, buf_size, "Unknown(%u)", (unsigned)proto);
    return buf;
}

enum packet_parse_status parse_ethernet_ipv4_packet(const uint8_t *packet,
                                                    size_t caplen,
                                                    struct parsed_packet *out) {
    const uint8_t *ip;
    size_t ip_caplen;
    uint16_t ethertype;
    int ihl;
    uint16_t frag_field;

    if (packet == NULL || out == NULL) {
        return PACKET_PARSE_ERROR_INVALID_ARGUMENT;
    }

    memset(out, 0, sizeof(*out));

    if (caplen < 14) {
        return PACKET_PARSE_SKIP_TOO_SHORT;
    }

    ethertype = ((uint16_t)packet[12] << 8) | packet[13];
    if (ethertype != 0x0800) {
        return PACKET_PARSE_SKIP_NON_IPV4;
    }

    if (caplen < 34) {
        return PACKET_PARSE_SKIP_TOO_SHORT;
    }

    ip = packet + 14;
    ip_caplen = caplen - 14;
    if ((ip[0] >> 4) != 4) {
        return PACKET_PARSE_SKIP_INVALID_IPV4;
    }

    ihl = (ip[0] & 0x0F) * 4;
    if (ihl < 20 || ip_caplen < (size_t)ihl) {
        return PACKET_PARSE_SKIP_INVALID_IPV4;
    }

    out->protocol_number = ip[9];
    if (inet_ntop(AF_INET, ip + 12, out->src_ip, sizeof(out->src_ip)) == NULL) {
        return PACKET_PARSE_SKIP_INVALID_IPV4;
    }
    if (inet_ntop(AF_INET, ip + 16, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        return PACKET_PARSE_SKIP_INVALID_IPV4;
    }

    {
        char proto_buf[PACKET_PROTOCOL_NAME_MAX];
        const char *protocol_name = proto_name(out->protocol_number,
                                               proto_buf,
                                               sizeof(proto_buf));
        snprintf(out->protocol_name,
                 sizeof(out->protocol_name),
                 "%s",
                 protocol_name);
    }

    frag_field = ((uint16_t)ip[6] << 8) | ip[7];
    if ((frag_field & 0x2000u) == 0 && (frag_field & 0x1FFFu) == 0 &&
        (out->protocol_number == 6 || out->protocol_number == 17) &&
        ip_caplen >= (size_t)(ihl + 4)) {
        const uint8_t *l4 = ip + ihl;
        out->has_ports = 1;
        out->src_port = ((uint16_t)l4[0] << 8) | l4[1];
        out->dst_port = ((uint16_t)l4[2] << 8) | l4[3];
    }

    return PACKET_PARSE_OK;
}

const char *packet_parse_status_name(enum packet_parse_status status) {
    switch (status) {
        case PACKET_PARSE_OK:
            return "PACKET_PARSE_OK";
        case PACKET_PARSE_SKIP_TOO_SHORT:
            return "PACKET_PARSE_SKIP_TOO_SHORT";
        case PACKET_PARSE_SKIP_NON_IPV4:
            return "PACKET_PARSE_SKIP_NON_IPV4";
        case PACKET_PARSE_SKIP_INVALID_IPV4:
            return "PACKET_PARSE_SKIP_INVALID_IPV4";
        case PACKET_PARSE_ERROR_INVALID_ARGUMENT:
            return "PACKET_PARSE_ERROR_INVALID_ARGUMENT";
        default:
            return "PACKET_PARSE_UNKNOWN_STATUS";
    }
}
