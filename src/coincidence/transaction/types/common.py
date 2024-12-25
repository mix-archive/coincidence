from typing import IO


def encode_num(num: int | bool):
    """Encode an integer as a byte array.

    The stacks hold byte vectors. When used as numbers, byte vectors are interpreted as
    little-endian variable-length integers with the most significant bit determining the
    sign of the integer. Thus 0x81 represents -1. 0x80 is another representation of zero
    (so called negative 0). Positive 0 is represented by a null-length vector. Byte
    vectors are interpreted as Booleans where False is represented by any representation
    of zero and True is represented by any representation of non-zero.
    """
    if num == 0:
        return b""
    ret = bytearray()
    ret += (abs_num := abs(num)).to_bytes((abs_num.bit_length() + 7) // 8, "little")
    if ret[-1] & 0x80:
        ret.append(0x00 if num > 0 else 0x80)
    elif num < 0:
        ret[-1] |= 0x80
    return bytes(ret)


def decode_num(data: bytes):
    """Decode a byte array as an integer."""
    if not data:
        return 0
    negative = data[-1] & 0x80
    data = data[:-1] + bytes([last] if (last := data[-1] & 0x7F) else [])
    return int.from_bytes(data, "little") * (-1 if negative else 1)


class varint(int):  # noqa:N801
    r"""Variable-length integer.

    This class is used to represent a variable-length integer in the Bitcoin
    protocol. It is a subclass of the built-in `int` class, so it can be used
    like a regular integer. The value of the integer is stored in the `value`
    attribute.

    The `serialize` method is used to serialize the integer into a sequence of
    bytes. The `deserialize` method is used to deserialize a sequence of bytes
    into an integer.

    Example:
        >>> value = varint(0x12345678)
        >>> value.serialize()
        b'\xfd\x78\x56\x34\x12'
        >>> varint.deserialize(b'\xfd\x78\x56\x34\x12')
        varint(0x12345678)

    Reference: https://developer.bitcoin.org/reference/transactions.html#compactsize-unsigned-integers

    """

    def serialize(self):
        """Serialize the variable-length integer into a sequence of bytes."""
        if (bit_length := self.bit_length()) <= 8 and self < 0xFD:  # noqa: PLR2004
            return self.to_bytes(1, "little")
        if bit_length <= 16:  # noqa: PLR2004
            return b"\xfd" + self.to_bytes(2, "little")
        if bit_length <= 32:  # noqa: PLR2004
            return b"\xfe" + self.to_bytes(4, "little")
        return b"\xff" + self.to_bytes(8, "little")

    @classmethod
    def deserialize(cls, data: IO[bytes]):
        """Deserialize a sequence of bytes into a variable-length integer."""
        match data.read(1):
            case b"\xfd":
                return cls.from_bytes(data.read(2), "little")
            case b"\xfe":
                return cls.from_bytes(data.read(4), "little")
            case b"\xff":
                return cls.from_bytes(data.read(8), "little")
            case byte:
                return cls.from_bytes(byte, "little")
