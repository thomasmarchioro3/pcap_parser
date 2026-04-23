type PacketRow = tuple[float, str, str, str, int | None, int | None]


def parse_packets(filename: str, /) -> list[PacketRow]: ...
