import re
import struct
from pathlib import Path

import pandas as pd
import pytest

from pcap_parser import parse_pcap

EXAMPLE_PCAP = str(Path(__file__).parent.parent / "data" / "example.pcap")

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
                                 "src_port", "dst_port"]


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


# ---------------------------------------------------------------------------
# Non-TCP/UDP ports are NaN (synthesised ICMP pcap)
# ---------------------------------------------------------------------------

@pytest.fixture
def icmp_pcap(tmp_path):
    """Build a minimal valid pcap containing one ICMP echo request."""

    def cksum(data):
        if len(data) % 2:
            data += b"\x00"
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i + 1]
            s = (s + w) & 0xFFFF
        return (~s) & 0xFFFF

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

    pcap_global = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    pcap_rec = struct.pack("<IIII", 1_000_000, 0, len(frame), len(frame)) + frame

    path = tmp_path / "icmp.pcap"
    path.write_bytes(pcap_global + pcap_rec)
    return str(path)


def test_non_tcp_udp_ports_are_nan(icmp_pcap):
    df = parse_pcap(icmp_pcap)
    assert len(df) == 1
    assert df.iloc[0]["protocol"] == "ICMP"
    assert pd.isna(df.iloc[0]["src_port"])
    assert pd.isna(df.iloc[0]["dst_port"])


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
                                 "src_port", "dst_port"]
    assert len(df) == 0
