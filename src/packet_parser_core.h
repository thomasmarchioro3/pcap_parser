#ifndef PACKET_PARSER_CORE_H
#define PACKET_PARSER_CORE_H

#include <arpa/inet.h>
#include <stddef.h>
#include <stdint.h>

#define PACKET_PROTOCOL_NAME_MAX 32

enum packet_parse_status {
    PACKET_PARSE_OK = 0,
    PACKET_PARSE_SKIP_TOO_SHORT,
    PACKET_PARSE_SKIP_NON_IPV4,
    PACKET_PARSE_SKIP_INVALID_IPV4,
    PACKET_PARSE_ERROR_INVALID_ARGUMENT
};

struct parsed_packet {
    uint8_t protocol_number;
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    char protocol_name[PACKET_PROTOCOL_NAME_MAX];
    int has_ports;
    uint16_t src_port;
    uint16_t dst_port;
    int has_payload_size;
    uint16_t payload_size;
};

enum packet_parse_status parse_ethernet_ipv4_packet(const uint8_t *packet,
                                                    size_t caplen,
                                                    struct parsed_packet *out);

const char *packet_parse_status_name(enum packet_parse_status status);

#endif
