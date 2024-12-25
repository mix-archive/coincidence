from io import BytesIO

import pytest

from .common import decode_num, encode_num, varint


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0x00, b"\x00"),
        (0xFC, b"\xfc"),
        (0xDEAD, b"\xfd\xad\xde"),
        (0xFFFF, b"\xfd\xff\xff"),
        (0xDEADBEEF, b"\xfe\xef\xbe\xad\xde"),
        (0xFFFFFFFF, b"\xfe\xff\xff\xff\xff"),
        (0xDEADBEEFDEADBEEF, b"\xff\xef\xbe\xad\xde\xef\xbe\xad\xde"),
    ],
)
def test_varint_serialization(value: int, expected: bytes):
    serialized = varint(value).serialize()
    assert serialized == expected
    deserialized = varint.deserialize(BytesIO(serialized))
    assert deserialized == value


@pytest.mark.parametrize(
    ("num", "expected"),
    [
        (0x00, b""),
        (0x01, b"\x01"),
        (0x7F, b"\x7f"),
        (-0x7F, b"\xff"),
        (0x80, b"\x80\x00"),
        (-0x80, b"\x80\x80"),
        (0xFF, b"\xff\x00"),
        (-0xFF, b"\xff\x80"),
        (0x100, b"\x00\x01"),
        (-0x100, b"\x00\x81"),
        (0x7FFF, b"\xff\x7f"),
        (-0x7FFF, b"\xff\xff"),
        (0x8000, b"\x00\x80\x00"),
        (-0x8000, b"\x00\x80\x80"),
    ],
    ids=(
        lambda x: repr(hex(x))  # pyright:ignore[reportAny]
        if isinstance(x, int)
        else repr(x.hex())
        if isinstance(x, bytes)
        else x
    ),
)
def test_encode_num(num: int, expected: bytes):
    assert encode_num(num) == expected
    assert decode_num(expected) == num
