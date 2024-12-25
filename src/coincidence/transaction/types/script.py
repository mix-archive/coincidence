import abc
from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntFlag, auto
from typing import IO, ClassVar, Self, override

from base58 import b58decode_check

from coincidence.crypto.keypair import BitcoinPublicKey
from coincidence.crypto.utils import RIPEMD160

from .common import decode_num, encode_num, varint
from .opcode import (
    Command,
    TransactionOpCode,
    build_script_bytecode,
    dissect_script_bytecode,
    read_script_bytecode,
)


class ScriptDeserializationFlag(IntFlag):
    FROM_COINBASE = auto()
    FROM_INPUT = auto()
    FROM_OUTPUT = auto()

    SEGREGATED_WITNESS = auto()
    TAPROOT = auto()


class BaseTransactionScript(abc.ABC):
    dispatches: ClassVar[set[type[Self]]] = set()

    @property
    @abc.abstractmethod
    def bytecode(self) -> bytes:
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        raise NotImplementedError

    @classmethod
    def deserialize(
        cls, reader: IO[bytes], flags: ScriptDeserializationFlag
    ) -> "BaseTransactionScript":
        bytecode = read_script_bytecode(reader)
        for dispatch in cls.dispatches:
            if dispatch in (CommonTransactionScript, cls):
                continue
            if script := dispatch.from_bytecode(bytecode, flags):
                return script
        return CommonTransactionScript(bytecode)

    def serialize(self) -> bytes:
        bytecode = self.bytecode
        return varint(len(bytecode)).serialize() + bytecode

    @override
    @classmethod
    def __subclasshook__(cls, subclass: type[Self], /) -> bool:
        cls.dispatches.add(subclass)
        return super().__subclasshook__(subclass)

    @property
    def commands(self) -> tuple[Command, ...]:
        return dissect_script_bytecode(self.bytecode)

    @override
    def __repr__(self):
        try:
            commands = repr([*self.commands])
        except ValueError:
            commands = "..."
        bytecode = repr(self.bytecode)
        if len(bytecode) > 32:  # noqa: PLR2004
            bytecode = bytecode[:16] + " [...] " + bytecode[-16:]
        return f"{self.__class__.__name__}({commands=:s}, {bytecode=:s})"

    def __add__(self, other: Self):
        return CommonTransactionScript(self.bytecode + other.bytecode)


@dataclass(frozen=True, repr=False)
class CommonTransactionScript(BaseTransactionScript):
    _bytecode: bytes = b""

    @property
    @override
    def bytecode(self) -> bytes:
        return self._bytecode

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        return cls(bytecode)

    @classmethod
    def from_commands(cls, commands: Iterable[Command]) -> Self:
        return cls(build_script_bytecode(commands))


@dataclass(frozen=True, repr=False)
class CoinbaseScript(BaseTransactionScript):
    height: int | None = None
    other_data: bytes = b""

    @property
    @override
    def bytecode(self) -> bytes:
        commands = [*self.commands]
        if self.height:
            commands.insert(0, encode_num(self.height))
        return build_script_bytecode(commands)

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_COINBASE:
            return None
        commands = dissect_script_bytecode(bytecode)
        if (
            commands
            and isinstance(height_data := commands[0], bytes)
            and 0 < (height := decode_num(height_data)) < (1 << 32)
        ):
            return cls(height, build_script_bytecode(commands[1:]))
        return cls(other_data=bytecode)


@dataclass(frozen=True, repr=False)
class PayToPublicKeyScript(BaseTransactionScript):
    pubkey: BitcoinPublicKey

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode([self.pubkey.sec, TransactionOpCode.OP_CHECKSIG])

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_OUTPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (bytes(pubkey), TransactionOpCode.OP_CHECKSIG) if (
                len(pubkey) in (32 + 1, 64 + 1)
            ):
                pk = BitcoinPublicKey.from_sec(pubkey)
                return cls(pk)
            case _:
                return None


@dataclass(frozen=True, repr=False)
class PayToPublicKeyHashScript(BaseTransactionScript):
    hash160: bytes

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode(
            [
                TransactionOpCode.OP_DUP,
                TransactionOpCode.OP_HASH160,
                self.hash160,
                TransactionOpCode.OP_EQUALVERIFY,
                TransactionOpCode.OP_CHECKSIG,
            ]
        )

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_OUTPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (
                TransactionOpCode.OP_DUP,
                TransactionOpCode.OP_HASH160,
                bytes(hash160),
                TransactionOpCode.OP_EQUALVERIFY,
                TransactionOpCode.OP_CHECKSIG,
            ) if len(hash160) == RIPEMD160().digest_size:
                return cls(hash160)
            case _:
                return None

    @classmethod
    def from_address(cls, address: str) -> Self:
        return cls(b58decode_check(address)[1:])


@dataclass(frozen=True, repr=False)
class SignatureScript(BaseTransactionScript):
    signature: bytes
    pubkey: BitcoinPublicKey

    @property
    @override
    def bytecode(self) -> bytes:
        return build_script_bytecode([self.signature, self.pubkey.sec])

    @classmethod
    @override
    def from_bytecode(
        cls, bytecode: bytes, flags: ScriptDeserializationFlag
    ) -> Self | None:
        if not flags & ScriptDeserializationFlag.FROM_INPUT:
            return None
        commands = dissect_script_bytecode(bytecode)
        match commands:
            case (bytes(signature), bytes(pubkey)) if (
                len(signature) > 0 and len(pubkey) > 0
            ):
                pk = BitcoinPublicKey.from_sec(pubkey)
                return cls(signature, pk)
            case _:
                return None
