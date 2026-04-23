import re
import struct
from pathlib import Path

import pandas as pd
import pytest

from pcap_parser import parse_pcap

EXAMPLE_PCAP = str(Path(__file__).parent.parent / "data" / "example.pcap")


def cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s = (s + w) & 0xFFFF
    return (~s) & 0xFFFF


def ethernet_frame(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def ipv4_header(src: bytes, dst: bytes, proto: int, payload_len: int, pkt_id: int = 1) -> bytes:
    total_len = 20 + payload_len
    header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        pkt_id,
        0,
        64,
        proto,
        0,
        src,
        dst,
    )
    return header[:10] + struct.pack(">H", cksum(header)) + header[12:]


def tcp_segment(sport: int, dport: int, payload: bytes = b"", flags: int = 0x18) -> bytes:
    return (
        struct.pack(
            ">HHIIBBHHH",
            sport,
            dport,
            0,
            0,
            0x50,
            flags,
            65535,
            0,
            0,
        )
        + payload
    )


def udp_segment(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def sctp_segment(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack(">HHII", sport, dport, 0, 0) + payload


def write_single_packet_pcap(tmp_path, filename: str, frame: bytes) -> str:
    pcap_global = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    pcap_record = struct.pack("<IIII", 1_000_000, 0, len(frame), len(frame)) + frame
    path = tmp_path / filename
    path.write_bytes(pcap_global + pcap_record)
    return str(path)

# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def test_smoke():
    df = parse_pcap(EXAMPLE_PCAP)
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def test_columns():
    df = parse_pcap(EXAMPLE_PCAP)
    assert list(df.columns) == ["timestamp", "src_ip", "dst_ip", "protocol",
                                 "src_port", "dst_port", "payload_size"]


def test_timestamp_dtype():
    df = parse_pcap(EXAMPLE_PCAP)
    assert pd.api.types.is_float_dtype(df["timestamp"])
    assert (df["timestamp"] > 0).all()


def test_ip_format():
    df = parse_pcap(EXAMPLE_PCAP)
    ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    assert df["src_ip"].apply(lambda x: bool(ip_re.match(x))).all()
    assert df["dst_ip"].apply(lambda x: bool(ip_re.match(x))).all()


# ---------------------------------------------------------------------------
# Packet counts
# ---------------------------------------------------------------------------

def test_no_arp_rows():
    """example.pcap has 2 ARP packets — they must not appear in the DataFrame."""
    df = parse_pcap(EXAMPLE_PCAP)
    # 7 total packets: 2 ARP (skipped) + 3 TCP + 2 UDP = 5 IP rows
    assert len(df) == 5


def test_protocol_values():
    df = parse_pcap(EXAMPLE_PCAP)
    assert set(df["protocol"].unique()) == {"TCP", "UDP"}


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

def test_tcp_ports():
    df = parse_pcap(EXAMPLE_PCAP)
    tcp = df[df["protocol"] == "TCP"]
    assert len(tcp) == 3
    assert tcp["src_port"].notna().all()
    assert tcp["dst_port"].notna().all()
    assert (tcp["src_port"] > 0).all()
    assert (tcp["dst_port"] > 0).all()


def test_known_tcp_row():
    df = parse_pcap(EXAMPLE_PCAP)
    # SYN and ACK from 192.168.1.1:54321 -> 10.0.0.1:80
    rows = df[(df["src_ip"] == "192.168.1.1") & (df["dst_port"] == 80.0)]
    assert len(rows) == 2
    assert (rows["protocol"] == "TCP").all()
    assert (rows["src_port"] == 54321.0).all()


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

def test_udp_ports():
    df = parse_pcap(EXAMPLE_PCAP)
    udp = df[df["protocol"] == "UDP"]
    assert len(udp) == 2
    assert udp["src_port"].notna().all()
    assert udp["dst_port"].notna().all()


def test_supported_protocol_payload_sizes_in_example_are_zero():
    df = parse_pcap(EXAMPLE_PCAP)
    supported = df[df["protocol"].isin(["TCP", "UDP"])]
    assert len(supported) == 5
    assert (supported["payload_size"] == 0).all()


# ---------------------------------------------------------------------------
# Non-TCP/UDP/SCTP transport fields are NaN (synthesised ICMP pcap)
# ---------------------------------------------------------------------------

@pytest.fixture
def icmp_pcap(tmp_path):
    """Build a minimal valid pcap containing one ICMP echo request."""

    src = bytes([192, 168, 1, 1])
    dst = bytes([192, 168, 1, 2])

    # ICMP echo request (type=8, code=0)
    icmp = struct.pack(">BBHHH", 8, 0, 0, 1, 1)
    icmp = struct.pack(">BBH", 8, 0, cksum(icmp)) + icmp[3:]

    # Minimal IPv4 header (no options)
    ip_hdr = struct.pack(">BBHHHBBH4s4s",
        0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0, src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack(">H", cksum(ip_hdr)) + ip_hdr[12:]

    eth = bytes(6) + bytes(6) + struct.pack(">H", 0x0800)
    frame = eth + ip_hdr + icmp

    return write_single_packet_pcap(tmp_path, "icmp.pcap", frame)


@pytest.fixture
def sctp_pcap(tmp_path):
    src_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])
    dst_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02])
    src_ip = bytes([203, 0, 113, 10])
    dst_ip = bytes([203, 0, 113, 20])
    payload = b"sctp!"
    segment = sctp_segment(2905, 2906, payload)
    ip_packet = ipv4_header(src_ip, dst_ip, 132, len(segment), pkt_id=99)
    frame = ethernet_frame(src_mac, dst_mac, 0x0800, ip_packet + segment)
    return write_single_packet_pcap(tmp_path, "sctp.pcap", frame)


@pytest.fixture
def transport_payloads_pcap(tmp_path):
    src_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])
    dst_mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02])
    tcp_src = bytes([192, 168, 1, 10])
    tcp_dst = bytes([10, 0, 0, 8])
    udp_src = bytes([192, 168, 1, 11])
    udp_dst = bytes([8, 8, 8, 8])
    sctp_src = bytes([203, 0, 113, 1])
    sctp_dst = bytes([203, 0, 113, 2])

    frames = []
    packets = [
        (tcp_src, tcp_dst, 6, tcp_segment(12345, 80, b"abcd"), 1),
        (udp_src, udp_dst, 17, udp_segment(5000, 53, b"hello"), 2),
        (sctp_src, sctp_dst, 132, sctp_segment(2905, 2906, b"chunk!"), 3),
    ]

    for src_ip, dst_ip, proto, segment, pkt_id in packets:
        ip_packet = ipv4_header(src_ip, dst_ip, proto, len(segment), pkt_id=pkt_id)
        frames.append(ethernet_frame(src_mac, dst_mac, 0x0800, ip_packet + segment))

    pcap_global = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = [
        struct.pack("<IIII", 1_000_000 + i, 0, len(frame), len(frame)) + frame
        for i, frame in enumerate(frames)
    ]

    path = tmp_path / "transport_payloads.pcap"
    path.write_bytes(pcap_global + b"".join(records))
    return str(path)


def test_non_tcp_udp_sctp_ports_and_payload_size_are_nan(icmp_pcap):
    df = parse_pcap(icmp_pcap)
    assert len(df) == 1
    assert df.iloc[0]["protocol"] == "ICMP"
    assert pd.isna(df.iloc[0]["src_port"])
    assert pd.isna(df.iloc[0]["dst_port"])
    assert pd.isna(df.iloc[0]["payload_size"])


def test_sctp_ports_and_payload_size(sctp_pcap):
    df = parse_pcap(sctp_pcap)
    assert len(df) == 1
    row = df.iloc[0]
    assert row["protocol"] == "SCTP"
    assert row["src_port"] == 2905.0
    assert row["dst_port"] == 2906.0
    assert row["payload_size"] == 5.0


def test_transport_payload_sizes(transport_payloads_pcap):
    df = parse_pcap(transport_payloads_pcap)
    assert list(df["protocol"]) == ["TCP", "UDP", "SCTP"]
    assert list(df["src_port"]) == [12345, 5000, 2905]
    assert list(df["dst_port"]) == [80, 53, 2906]
    assert list(df["payload_size"]) == [4, 5, 6]


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------

def test_file_not_found():
    with pytest.raises(OSError):
        parse_pcap("/nonexistent/path/file.pcap")


def test_non_ethernet_raises(tmp_path):
    """A pcap with DLT=113 (LINUX_SLL) must raise ValueError."""
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 113)
    path = tmp_path / "linux_sll.pcap"
    path.write_bytes(hdr)
    with pytest.raises(ValueError, match="Unsupported datalink type"):
        parse_pcap(str(path))


def test_empty_pcap(tmp_path):
    """A valid pcap with no packets returns an empty DataFrame with correct columns."""
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    path = tmp_path / "empty.pcap"
    path.write_bytes(hdr)
    df = parse_pcap(str(path))
    assert list(df.columns) == ["timestamp", "src_ip", "dst_ip", "protocol",
                                 "src_port", "dst_port", "payload_size"]
    assert len(df) == 0
