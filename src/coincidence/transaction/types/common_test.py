from io import BytesIO

import pytest

from .common import varint


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
