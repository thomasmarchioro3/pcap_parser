import pandas as pd
from . import _pcap_parser

COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "payload_size",
]


def parse_pcap(pcap_file: str) -> pd.DataFrame:
    rows = _pcap_parser.parse_packets(pcap_file)
    return pd.DataFrame(rows, columns=COLUMNS)
