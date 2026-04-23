#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "packet_parser_core.h"

#define ASSERT_TRUE(expr)                                                     \
    do {                                                                      \
        if (!(expr)) {                                                        \
            fprintf(stderr, "%s:%d: assertion failed: %s\n",                  \
                    __FILE__, __LINE__, #expr);                               \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#define ASSERT_EQ_INT(actual, expected)                                       \
    do {                                                                      \
        int actual_value = (actual);                                          \
        int expected_value = (expected);                                      \
        if (actual_value != expected_value) {                                 \
            fprintf(stderr, "%s:%d: expected %d, got %d\n",                   \
                    __FILE__, __LINE__, expected_value, actual_value);        \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#define ASSERT_STREQ(actual, expected)                                        \
    do {                                                                      \
        if (strcmp((actual), (expected)) != 0) {                              \
            fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n",           \
                    __FILE__, __LINE__, (expected), (actual));                \
            return 1;                                                         \
        }                                                                     \
    } while (0)

static void build_ipv4_frame(uint8_t *frame,
                             size_t frame_len,
                             uint8_t protocol,
                             uint16_t fragment_field,
                             const uint8_t src[4],
                             const uint8_t dst[4]) {
    memset(frame, 0, frame_len);

    frame[12] = 0x08;
    frame[13] = 0x00;

    frame[14] = 0x45;
    frame[16] = 0x00;
    frame[17] = (uint8_t)(frame_len - 14);
    frame[18] = 0x12;
    frame[19] = 0x34;
    frame[20] = (uint8_t)(fragment_field >> 8);
    frame[21] = (uint8_t)(fragment_field & 0xFF);
    frame[22] = 64;
    frame[23] = protocol;

    memcpy(frame + 26, src, 4);
    memcpy(frame + 30, dst, 4);
}

static int test_parse_tcp_packet(void) {
    static const uint8_t src[4] = {192, 168, 1, 10};
    static const uint8_t dst[4] = {10, 0, 0, 8};
    uint8_t frame[14 + 20 + 20];
    struct parsed_packet packet;
    enum packet_parse_status status;

    build_ipv4_frame(frame, sizeof(frame), 6, 0, src, dst);
    frame[34] = 0x30;
    frame[35] = 0x39;
    frame[36] = 0x00;
    frame[37] = 0x50;

    status = parse_ethernet_ipv4_packet(frame, sizeof(frame), &packet);

    ASSERT_EQ_INT(status, PACKET_PARSE_OK);
    ASSERT_EQ_INT(packet.protocol_number, 6);
    ASSERT_STREQ(packet.protocol_name, "TCP");
    ASSERT_STREQ(packet.src_ip, "192.168.1.10");
    ASSERT_STREQ(packet.dst_ip, "10.0.0.8");
    ASSERT_TRUE(packet.has_ports);
    ASSERT_EQ_INT(packet.src_port, 12345);
    ASSERT_EQ_INT(packet.dst_port, 80);
    return 0;
}

static int test_parse_icmp_packet_without_ports(void) {
    static const uint8_t src[4] = {172, 16, 0, 1};
    static const uint8_t dst[4] = {172, 16, 0, 2};
    uint8_t frame[14 + 20 + 8];
    struct parsed_packet packet;
    enum packet_parse_status status;

    build_ipv4_frame(frame, sizeof(frame), 1, 0, src, dst);
    status = parse_ethernet_ipv4_packet(frame, sizeof(frame), &packet);

    ASSERT_EQ_INT(status, PACKET_PARSE_OK);
    ASSERT_STREQ(packet.protocol_name, "ICMP");
    ASSERT_TRUE(!packet.has_ports);
    return 0;
}

static int test_skip_non_ipv4_frame(void) {
    uint8_t frame[14 + 20] = {0};
    struct parsed_packet packet;
    enum packet_parse_status status;

    frame[12] = 0x08;
    frame[13] = 0x06;

    status = parse_ethernet_ipv4_packet(frame, sizeof(frame), &packet);

    ASSERT_EQ_INT(status, PACKET_PARSE_SKIP_NON_IPV4);
    return 0;
}

static int test_fragmented_udp_packet_has_no_ports(void) {
    static const uint8_t src[4] = {192, 0, 2, 1};
    static const uint8_t dst[4] = {198, 51, 100, 9};
    uint8_t frame[14 + 20 + 8];
    struct parsed_packet packet;
    enum packet_parse_status status;

    build_ipv4_frame(frame, sizeof(frame), 17, 0x2000, src, dst);
    frame[34] = 0x1F;
    frame[35] = 0x90;
    frame[36] = 0x00;
    frame[37] = 0x35;

    status = parse_ethernet_ipv4_packet(frame, sizeof(frame), &packet);

    ASSERT_EQ_INT(status, PACKET_PARSE_OK);
    ASSERT_STREQ(packet.protocol_name, "UDP");
    ASSERT_TRUE(!packet.has_ports);
    return 0;
}

static int test_short_frame_is_skipped(void) {
    uint8_t frame[10] = {0};
    struct parsed_packet packet;
    enum packet_parse_status status;

    status = parse_ethernet_ipv4_packet(frame, sizeof(frame), &packet);

    ASSERT_EQ_INT(status, PACKET_PARSE_SKIP_TOO_SHORT);
    return 0;
}

int main(void) {
    struct {
        const char *name;
        int (*fn)(void);
    } tests[] = {
        {"parse_tcp_packet", test_parse_tcp_packet},
        {"parse_icmp_packet_without_ports", test_parse_icmp_packet_without_ports},
        {"skip_non_ipv4_frame", test_skip_non_ipv4_frame},
        {"fragmented_udp_packet_has_no_ports", test_fragmented_udp_packet_has_no_ports},
        {"short_frame_is_skipped", test_short_frame_is_skipped}
    };
    size_t i;

    for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int rc = tests[i].fn();
        if (rc != 0) {
            fprintf(stderr, "test failed: %s\n", tests[i].name);
            return rc;
        }
    }

    puts("C packet parser tests passed");
    return 0;
}
