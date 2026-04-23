# packet-parser

A Python library for parsing pcap files and extracting L3 packet information into a pandas DataFrame.

Packet extraction is implemented as a C extension using the [Python C API](https://docs.python.org/3/c-api/) and [libpcap](https://www.tcpdump.org/).
The raw Ethernet/IPv4 parsing logic also lives in a standalone C module so it can be unit tested without going through Python.

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

## Building And Rebuilding

`uv sync` installs the project as an editable package and builds the `_pcap_parser` extension module.

This project also configures `tool.uv.cache-keys` so changes to files under `src/**/*.c` and `src/**/*.h` invalidate uv's local build cache. In practice, after editing the C sources, rerunning:

```bash
uv sync
```

will rebuild the local `.so`.

If you want to force a rebuild even when uv believes the package is already fresh, use:

```bash
uv sync --reinstall-package pcap-parser
```

For editor support, the repository includes a stub file at `pcap_parser/_pcap_parser.pyi`, and `pyproject.toml` points pyright at the local `.venv`.

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
| `src_port` | `float64` | Source port — `NaN` for protocols other than TCP, UDP, and SCTP |
| `dst_port` | `float64` | Destination port — `NaN` for protocols other than TCP, UDP, and SCTP |
| `payload_size` | `float64` | Transport payload size in bytes after the TCP, UDP, or SCTP header — `NaN` when unavailable |

**Notes:**
- Only IPv4 packets are included; non-IP frames (ARP, IPv6, VLAN, etc.) are silently skipped.
- Only Ethernet (DLT_EN10MB) captures are supported; other datalink types raise `ValueError`.
- IP fragments are included but `src_port`, `dst_port`, and `payload_size` are `NaN`.

## Project structure

```
pcap_parser/
├── src/
│   ├── _pcap_parser.c          # C extension: libpcap + Python C API
│   ├── packet_parser_core.c    # Reusable Ethernet/IPv4 parsing logic
│   └── packet_parser_core.h    # Shared parser API for the extension and C tests
├── pcap_parser/
│   ├── __init__.py             # Public API: exposes parse_pcap
│   ├── _pcap_parser.pyi        # Type stub for the compiled extension module
│   └── parser.py               # Wraps the C extension, builds the DataFrame
├── data/
│   └── example.pcap            # Small reference capture (TCP + UDP) for tests
├── tests/
│   ├── test_parser.py          # Python-facing smoke and unit tests
│   ├── test_c_parser.py        # Builds and runs the standalone C parser tests
│   └── c/test_packet_parser.c  # Minimal dependency-free C test executable
├── setup.py                    # C extension build definition (libpcap detection)
└── pyproject.toml              # Project metadata and build-system config
```

## Running tests

```bash
uv run pytest tests/ -v
```

That command now also compiles and runs the standalone C parser tests with the system C compiler.
