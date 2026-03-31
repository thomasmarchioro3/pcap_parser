#!/usr/bin/env python3
"""Generate data/example.pcap for pcap_parser tests.

Produces 7 packets:
  - 2 ARP  (non-IP, skipped by parser)
  - 3 TCP  (192.168.1.1:54321 <-> 10.0.0.1:80)
  - 2 UDP  (192.168.1.1:5000  <-> 8.8.8.8:53)
"""
import os
import struct


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s = (s + w) & 0xFFFF
    return (~s) & 0xFFFF


def ip_header(src: bytes, dst: bytes, proto: int, payload_len: int,
              pkt_id: int = 1) -> bytes:
    total_len = 20 + payload_len
    hdr = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, pkt_id, 0, 64, proto, 0, src, dst,
    )
    ck = checksum(hdr)
    return hdr[:10] + struct.pack(">H", ck) + hdr[12:]


def tcp_segment(sport: int, dport: int, seq: int = 0, ack: int = 0,
                flags: int = 0x02) -> bytes:
    return struct.pack(
        ">HHIIBBHHH",
        sport, dport, seq, ack,
        0x50,   # data offset=5, reserved=0
        flags,  # SYN=0x02, ACK=0x10, SYN+ACK=0x12
        65535,  # window
        0,      # checksum (not validated by libpcap for offline reads)
        0,      # urgent pointer
    )


def udp_segment(sport: int, dport: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def ethernet_frame(src_mac: bytes, dst_mac: bytes, ethertype: int,
                   payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def arp_frame(src_mac: bytes, src_ip: bytes, dst_ip: bytes,
              op: int = 1) -> bytes:
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op)
    arp += src_mac + src_ip + b"\x00" * 6 + dst_ip
    dst_mac = b"\xff\xff\xff\xff\xff\xff" if op == 1 else src_mac
    return ethernet_frame(src_mac, dst_mac, 0x0806, arp)


def pcap_record(frame: bytes, ts_sec: int, ts_usec: int = 0) -> bytes:
    n = len(frame)
    return struct.pack("<IIII", ts_sec, ts_usec, n, n) + frame


def pcap_global_header() -> bytes:
    return struct.pack("<IHHiIII",
        0xa1b2c3d4,  # magic (microsecond timestamps)
        2, 4,        # version 2.4
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        1,           # DLT_EN10MB
    )


def main() -> None:
    mac1 = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
    mac2 = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02])
    ip1 = bytes([192, 168, 1, 1])
    ip2 = bytes([10, 0, 0, 1])
    ip_dns = bytes([8, 8, 8, 8])

    packets = []
    t = 1_000_000  # base timestamp (seconds)

    # --- ARP request (non-IP, parser must skip) ---
    packets.append(pcap_record(arp_frame(mac1, ip1, ip2, op=1), t)); t += 1

    # --- ARP reply (non-IP, parser must skip) ---
    packets.append(pcap_record(arp_frame(mac2, ip2, ip1, op=2), t)); t += 1

    # --- TCP SYN: 192.168.1.1:54321 -> 10.0.0.1:80 ---
    seg = tcp_segment(54321, 80, seq=1000, flags=0x02)
    pkt = ip_header(ip1, ip2, 6, len(seg), pkt_id=1)
    packets.append(pcap_record(ethernet_frame(mac1, mac2, 0x0800, pkt + seg), t)); t += 1

    # --- TCP SYN-ACK: 10.0.0.1:80 -> 192.168.1.1:54321 ---
    seg = tcp_segment(80, 54321, seq=2000, ack=1001, flags=0x12)
    pkt = ip_header(ip2, ip1, 6, len(seg), pkt_id=2)
    packets.append(pcap_record(ethernet_frame(mac2, mac1, 0x0800, pkt + seg), t)); t += 1

    # --- TCP ACK: 192.168.1.1:54321 -> 10.0.0.1:80 ---
    seg = tcp_segment(54321, 80, seq=1001, ack=2001, flags=0x10)
    pkt = ip_header(ip1, ip2, 6, len(seg), pkt_id=3)
    packets.append(pcap_record(ethernet_frame(mac1, mac2, 0x0800, pkt + seg), t)); t += 1

    # --- UDP DNS query: 192.168.1.1:5000 -> 8.8.8.8:53 ---
    seg = udp_segment(5000, 53)
    pkt = ip_header(ip1, ip_dns, 17, len(seg), pkt_id=4)
    packets.append(pcap_record(ethernet_frame(mac1, mac2, 0x0800, pkt + seg), t)); t += 1

    # --- UDP DNS response: 8.8.8.8:53 -> 192.168.1.1:5000 ---
    seg = udp_segment(53, 5000)
    pkt = ip_header(ip_dns, ip1, 17, len(seg), pkt_id=5)
    packets.append(pcap_record(ethernet_frame(mac2, mac1, 0x0800, pkt + seg), t)); t += 1

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example.pcap")
    with open(out, "wb") as f:
        f.write(pcap_global_header())
        for p in packets:
            f.write(p)

    print(f"Wrote {len(packets)} packets to {out}")
    print("  2 ARP  — skipped by parser (non-IP)")
    print("  3 TCP  — 192.168.1.1:54321 <-> 10.0.0.1:80")
    print("  2 UDP  — 192.168.1.1:5000  <-> 8.8.8.8:53")


if __name__ == "__main__":
    main()
