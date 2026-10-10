"""Deterministic synthetic WAL builders; no database or third-party packages."""

from pathlib import Path
import struct


PAGE_SIZE = 8192
SEGMENT_SIZE = 1024 * 1024
MAGIC = {16: 0xD113, 17: 0xD116, 18: 0xD118}


def crc32c(data: bytes, crc: int = 0) -> int:
    """Independent bitwise fixture checksum, with the standard check vector."""
    state = crc ^ 0xFFFFFFFF
    for byte in data:
        state ^= byte
        for _ in range(8):
            state = (state >> 1) ^ (0x82F63B78 if state & 1 else 0)
    return state ^ 0xFFFFFFFF


def main_body(data: bytes) -> bytes:
    if not data:
        return b""
    if len(data) < 256:
        return bytes((255, len(data))) + data
    return b"\xfe" + struct.pack("<I", len(data)) + data


def record_bytes(
    body: bytes = b"",
    xid: int = 0,
    rmid: int = 10,
    info: int = 0,
    previous_lsn: int = 0,
) -> bytes:
    header = struct.pack("<IIQBB2x", 24 + len(body), xid, previous_lsn, info, rmid)
    checksum = crc32c(header, crc32c(body))
    return header + struct.pack("<I", checksum) + body


def block_header(
    block_id: int = 0,
    flags: int = 0x20,
    data_size: int = 0,
    relation: tuple[int, int, int] = (1663, 5, 42),
    number: int = 0,
    image_header: bytes = b"",
) -> bytes:
    result = struct.pack("<BBH", block_id, flags, data_size) + image_header
    if not flags & 0x80:
        result += struct.pack("<III", *relation)
    return result + struct.pack("<I", number)


class WalFixture:
    def __init__(
        self,
        directory: Path,
        major: int = 18,
        segment_size: int = SEGMENT_SIZE,
        timeline: int = 1,
        system_identifier: int = 12345,
        start_segment: int = 1,
    ):
        self.directory = directory
        self.major = major
        self.segment_size = segment_size
        self.timeline = timeline
        self.system_identifier = system_identifier
        self.segments: dict[int, bytearray] = {}
        self.position = start_segment * segment_size + 40
        self.last_lsn = 0
        self._page_header(start_segment * segment_size, 0)

    def filename(self, segment: int) -> str:
        per_log = (1 << 32) // self.segment_size
        return f"{self.timeline:08X}{segment // per_log:08X}{segment % per_log:08X}"

    def _page_header(self, address: int, remaining: int) -> int:
        segment, offset = divmod(address, self.segment_size)
        storage = self.segments.setdefault(segment, bytearray(self.segment_size))
        long_header = offset == 0
        flags = (2 if long_header else 0) | (1 if remaining else 0)
        header = struct.pack("<HHIQI4x", MAGIC[self.major], flags,
                             self.timeline, address, remaining)
        if long_header:
            header += struct.pack("<QII", self.system_identifier, self.segment_size, PAGE_SIZE)
        storage[offset:offset + len(header)] = header
        return len(header)

    def append(
        self,
        main_data: bytes = b"",
        body: bytes | None = None,
        xid: int = 0,
        rmid: int = 10,
        info: int = 0,
        previous_lsn: int | None = None,
    ) -> int:
        if self.position % PAGE_SIZE == 0:
            self.position += self._page_header(self.position, 0)
        lsn = self.position
        raw = record_bytes(main_body(main_data) if body is None else body,
                           xid, rmid, info,
                           self.last_lsn if previous_lsn is None else previous_lsn)
        consumed = 0
        while consumed < len(raw):
            segment, offset = divmod(self.position, self.segment_size)
            take = min(len(raw) - consumed, PAGE_SIZE - self.position % PAGE_SIZE)
            self.segments[segment][offset:offset + take] = raw[consumed:consumed + take]
            self.position += take
            consumed += take
            if consumed < len(raw):
                self.position += self._page_header(self.position, len(raw) - consumed)
        self.position = (self.position + 7) & ~7
        self.last_lsn = lsn
        if rmid == 0 and info & 0xF0 == 0x40:
            self.position = ((self.position + self.segment_size - 1) // self.segment_size) * self.segment_size
        return lsn

    def write(self) -> list[Path]:
        self.directory.mkdir(parents=True, exist_ok=True)
        result = []
        for segment, storage in sorted(self.segments.items()):
            path = self.directory / self.filename(segment)
            path.write_bytes(storage)
            result.append(path)
        return result
