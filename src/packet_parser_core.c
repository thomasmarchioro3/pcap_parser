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

static int is_supported_transport_protocol(uint8_t proto) {
    return proto == 6 || proto == 17 || proto == 132;
}

static int is_unfragmented_ipv4_packet(uint16_t frag_field) {
    return (frag_field & 0x3FFFu) == 0;
}

static int parse_transport_payload_size(uint8_t protocol,
                                        const uint8_t *l4,
                                        size_t l4_caplen,
                                        uint16_t l4_length,
                                        uint16_t *payload_size) {
    uint16_t header_length;

    switch (protocol) {
        case 6:
            if (l4_caplen < 13 || l4_length < 20) {
                return 0;
            }
            header_length = (uint16_t)((l4[12] >> 4) * 4);
            if (header_length < 20 || header_length > l4_length) {
                return 0;
            }
            *payload_size = (uint16_t)(l4_length - header_length);
            return 1;
        case 17:
            if (l4_length < 8) {
                return 0;
            }
            *payload_size = (uint16_t)(l4_length - 8);
            return 1;
        case 132:
            if (l4_length < 12) {
                return 0;
            }
            *payload_size = (uint16_t)(l4_length - 12);
            return 1;
        default:
            return 0;
    }
}

enum packet_parse_status parse_ethernet_ipv4_packet(const uint8_t *packet,
                                                    size_t caplen,
                                                    struct parsed_packet *out) {
    const uint8_t *ip;
    const uint8_t *l4;
    size_t ip_caplen;
    size_t l4_caplen;
    uint16_t ethertype;
    uint16_t total_length;
    int ihl;
    uint16_t frag_field;
    uint16_t l4_length;

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

    total_length = ((uint16_t)ip[2] << 8) | ip[3];
    if (total_length < (uint16_t)ihl) {
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
    if (!is_supported_transport_protocol(out->protocol_number) ||
        !is_unfragmented_ipv4_packet(frag_field)) {
        return PACKET_PARSE_OK;
    }

    l4 = ip + ihl;
    l4_caplen = ip_caplen - (size_t)ihl;
    l4_length = (uint16_t)(total_length - (uint16_t)ihl);

    if (l4_length >= 4 && l4_caplen >= 4) {
        out->has_ports = 1;
        out->src_port = ((uint16_t)l4[0] << 8) | l4[1];
        out->dst_port = ((uint16_t)l4[2] << 8) | l4[3];
    }

    if (parse_transport_payload_size(out->protocol_number,
                                     l4,
                                     l4_caplen,
                                     l4_length,
                                     &out->payload_size)) {
        out->has_payload_size = 1;
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
