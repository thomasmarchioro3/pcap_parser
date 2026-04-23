import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _compiler_command() -> list[str] | None:
    env_cc = os.environ.get("CC")
    if env_cc:
        return shlex.split(env_cc)

    for compiler in ("cc", "gcc", "clang"):
        path = shutil.which(compiler)
        if path:
            return [path]

    return None


def test_c_packet_parser_unit_tests(tmp_path):
    compiler = _compiler_command()
    if compiler is None:
        pytest.skip("no C compiler available")

    binary = tmp_path / "test_packet_parser"
    compile_cmd = [
        *compiler,
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-O2",
        f"-I{ROOT / 'src'}",
        str(ROOT / "tests" / "c" / "test_packet_parser.c"),
        str(ROOT / "src" / "packet_parser_core.c"),
        "-o",
        str(binary),
    ]

    subprocess.run(
        compile_cmd,
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [str(binary)],
        check=True,
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
