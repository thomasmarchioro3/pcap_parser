import subprocess
from setuptools import setup, Extension


def pcap_libs():
    try:
        flags = subprocess.check_output(["pcap-config", "--libs"]).decode().split()
        return [f[2:] for f in flags if f.startswith("-l")]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ["pcap"]


def pcap_include_dirs():
    try:
        flags = subprocess.check_output(["pcap-config", "--cflags"]).decode().split()
        return [f[2:] for f in flags if f.startswith("-I")]
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []


ext = Extension(
    name="pcap_parser._pcap_parser",
    sources=["src/_pcap_parser.c", "src/packet_parser_core.c"],
    libraries=pcap_libs(),
    include_dirs=pcap_include_dirs(),
    extra_compile_args=["-std=c99", "-Wall", "-O2"],
)

setup(
    packages=["pcap_parser"],
    package_dir={"pcap_parser": "pcap_parser"},
    package_data={"pcap_parser": ["*.pyi", "py.typed"]},
    ext_modules=[ext],
)
