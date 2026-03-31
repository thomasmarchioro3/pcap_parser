# packet-parser

A Python library for parsing pcap files and extracting L3 packet information into a pandas DataFrame.

Packet extraction is implemented as a C extension using the [Python C API](https://docs.python.org/3/c-api/) and [libpcap](https://www.tcpdump.org/).

## Requirements

**System:**
- libpcap (`libpcap-dev` on Debian/Ubuntu)
- Python 3.12

**Python:** installed automatically via `uv sync` or `pip install`
- pandas ≥ 2.0

## Installation

```bash
# Install system dependency (if not already present)
sudo apt-get install -y libpcap-dev

# Install the package (builds the C extension automatically)
uv sync
```

For development (includes pytest):

```bash
uv sync --extra dev
```

> **Note:** `uv sync` must use a Python installation that includes C headers. If you hit a `Python.h: No such file or directory` error, run `uv python install 3.12.12` first — uv-managed Pythons bundle the necessary headers.

## Usage

```python
from pcap_parser import parse_pcap

df = parse_pcap("path/to/capture.pcap")
print(df)
```

### Output schema

| Column | Type | Description |
|---|---|---|
| `timestamp` | `float64` | Packet timestamp (Unix epoch, microsecond precision) |
| `src_ip` | `object` (str) | Source IPv4 address (dotted-decimal) |
| `dst_ip` | `object` (str) | Destination IPv4 address (dotted-decimal) |
| `protocol` | `object` (str) | IANA protocol name (e.g. `TCP`, `UDP`, `ICMP`) |
| `src_port` | `float64` | Source port — `NaN` for non-TCP/UDP protocols |
| `dst_port` | `float64` | Destination port — `NaN` for non-TCP/UDP protocols |

**Notes:**
- Only IPv4 packets are included; non-IP frames (ARP, IPv6, VLAN, etc.) are silently skipped.
- Only Ethernet (DLT_EN10MB) captures are supported; other datalink types raise `ValueError`.
- IP fragments are included but `src_port`/`dst_port` are `NaN`.

## Project structure

```
pcap_parser/
├── src/
│   └── _pcap_parser.c        # C extension: libpcap + Python C API
├── pcap_parser/
│   ├── __init__.py             # Public API: exposes parse_pcap
│   └── parser.py               # Wraps the C extension, builds the DataFrame
├── data/
│   └── example.pcap            # Small reference capture (TCP + UDP) for tests
├── tests/
│   └── test_parser.py          # Smoke and unit tests
├── setup.py                    # C extension build definition (libpcap detection)
└── pyproject.toml              # Project metadata and build-system config
```

## Running tests

```bash
uv run pytest tests/ -v
```
