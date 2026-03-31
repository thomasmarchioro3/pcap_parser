# CLAUDE.md — packet-parser

Reference for Claude Code when working on this project.

## What this project is

A Python library exposing `parse_pcap(pcap_file: str) -> pd.DataFrame`.

The C extension (`src/_pcap_parser.c`) handles all pcap reading and packet parsing via libpcap. The Python layer (`pcap_parser/parser.py`) only wraps the result in a DataFrame. Top-level import: `from pcap_parser import parse_pcap`.

## Key files

| File | Role |
|---|---|
| `src/_pcap_parser.c` | C extension — libpcap + Python C API |
| `pcap_parser/__init__.py` | Re-exports `parse_pcap` |
| `pcap_parser/parser.py` | Calls C ext, builds `pd.DataFrame` |
| `setup.py` | C extension definition; uses `pcap-config` to detect libpcap link flags |
| `pyproject.toml` | Build-system (`setuptools.build_meta`), deps, dev extras |
| `data/example.pcap` | Reference capture used by tests — **do not overwrite without checking first** |
| `tests/test_parser.py` | 13 tests: smoke, schema, packet counts, port extraction, error cases |

## Architecture: C extension design

- **Entry point**: `parse_packets(filename: str) -> list[tuple]`
- **libpcap flow**: `pcap_open_offline` → assert `DLT_EN10MB` → `pcap_loop` with `packet_handler` callback → `pcap_close`
- **Callback** accumulates a `PyList` of `PyTuple(float, str, str, str, int|None, int|None)` = `(timestamp, src_ip, dst_ip, protocol, src_port, dst_port)`
- **Protocol names**: static lookup table in C; fallback `"Unknown(N)"`
- **Non-IP frames** (ARP, IPv6, VLAN): silently skipped
- **Ports**: `Py_None` for non-TCP/UDP and IP fragments; pandas maps these to `NaN`/`float64`

## Build and test

```bash
# First-time setup (uv-managed Python required for C headers)
uv python install 3.12.12
uv sync --python 3.12.12 --extra dev

# Subsequent syncs (once .venv exists with the right Python)
uv sync --extra dev

# Run tests
uv run pytest tests/ -v

# Smoke check
uv run python -c "from pcap_parser import parse_pcap; print(parse_pcap('data/example.pcap'))"
```

## Important notes

- **System dependency**: libpcap (`libpcap-dev`) must be installed. `setup.py` uses `pcap-config` to get link flags and falls back to `-lpcap`.
- **Python headers**: the system Python 3.12 on this machine (`/usr/bin/python3.12`) does **not** include C headers. Always use the uv-managed `cpython-3.12.12` which bundles `Python.h`. The `.python-version` file currently pins to `3.12` — if `uv sync` fails with `Python.h not found`, run `uv sync --python 3.12.12`.
- **example.pcap**: the file in `data/` was provided by the user and contains specific packets chosen for the tests. Do not regenerate or overwrite it without explicitly checking with the user. `data/generate_example_pcap.py` exists as a reference for the pcap format but should not be run automatically.
- **C extension name**: `pcap_parser._pcap_parser` (note the leading underscore). The compiled `.so` lives inside the `pcap_parser/` package directory after build.
- **Editable install quirk**: setuptools can misdetect the layout as a `src` layout because `src/` exists. The `setup.py` explicitly sets `packages=["pcap_parser"]` and `package_dir={"pcap_parser": "pcap_parser"}` to prevent this.

## Test fixture for non-TCP/UDP

The `test_non_tcp_udp_ports_are_nan` test synthesises a minimal ICMP pcap at runtime using stdlib `struct` — no scapy or external dependency needed.

## Current limitations (v1 scope)

- IPv4 only (IPv6 skipped silently)
- Ethernet (DLT_EN10MB) only
- No TCP reassembly or application-layer decoding
