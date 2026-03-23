"""
protocol.py — Binary framing layer (#11 protobuf, #12 compression)

Frame format:  [4-byte big-endian length][protobuf-serialised Envelope]
Compression:   marker byte 0x01 = zlib compressed, 0x00 = raw
"""
from __future__ import annotations

import struct
import zlib

import messages_pb2 as pb

MAX_FRAME_BYTES = 50 * 1024 * 1024
COMPRESS_THRESHOLD = 512
_msg_counter = 0


def _next_id() -> int:
    global _msg_counter
    _msg_counter += 1
    return _msg_counter


async def read_frame(reader) -> bytes:
    header = await reader.readexactly(4)
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"frame too large: {length}")
    return await reader.readexactly(length)


async def write_frame(writer, payload: bytes) -> None:
    writer.write(struct.pack("!I", len(payload)) + payload)
    await writer.drain()


async def send_envelope(writer, envelope: pb.Envelope, compress: bool = True) -> None:
    raw = envelope.SerializeToString()
    if compress and len(raw) >= COMPRESS_THRESHOLD:
        frame_payload = b"\x01" + zlib.compress(raw, level=6)
    else:
        frame_payload = b"\x00" + raw
    await write_frame(writer, frame_payload)


async def recv_envelope(reader) -> pb.Envelope:
    frame = await read_frame(reader)
    if not frame:
        raise ConnectionError("empty frame")
    marker, data = frame[0:1], frame[1:]
    if marker == b"\x01":
        data = zlib.decompress(data)
    env = pb.Envelope()
    env.ParseFromString(data)
    return env


def make_env(client_id: str = "", group: str = "") -> pb.Envelope:
    env = pb.Envelope()
    env.msg_id = _next_id()
    env.client_id = client_id
    env.group = group
    return env
