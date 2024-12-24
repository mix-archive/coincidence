from dataclasses import dataclass
from enum import IntEnum, auto
from functools import cached_property
from itertools import zip_longest
from typing import Self, cast

from coincidence.crypto.utils import sha256

type MerkleTreePair = bytes | tuple[bytes, bytes] | tuple["MerkleTree", "MerkleTree"]


class ProofPosition(IntEnum):
    LEFT = auto()
    RIGHT = auto()


@dataclass(frozen=True)
class MerkleTree:
    pair: MerkleTreePair

    def proof(self, target: bytes) -> list[tuple[bytes, ProofPosition]] | None:
        if target not in self:
            return None
        match self.pair:
            case bytes():
                return []
            case (bytes(left), bytes(right)) if left == target:
                return [(right, ProofPosition.RIGHT)]
            case (bytes(left), bytes(right)):
                return [(left, ProofPosition.LEFT)]
            case (left, right) if (found := left.proof(target)) is not None:
                return [*found, (right.hash, ProofPosition.RIGHT)]
            case (left, right) if (found := right.proof(target)) is not None:
                return [*found, (left.hash, ProofPosition.LEFT)]
            case _:  # pragma: no cover
                raise ValueError("Invalid state")

    @cached_property
    def hash(self) -> bytes:
        match self.pair:
            case bytes(hash_):
                return hash_
            case (bytes(left), bytes(right)):
                return sha256(sha256(left + right))
            case (left, right):
                return sha256(sha256(left.hash + right.hash))

    @cached_property
    def hashes(self) -> frozenset[bytes]:
        match self.pair:
            case bytes(hash_):
                return frozenset([hash_])
            case (bytes(left), bytes(right)) as pair:
                return frozenset(pair)
            case (left, right):
                return left.hashes | right.hashes

    def __contains__(self, hash_: bytes) -> bool:
        return hash_ in self.hashes

    @classmethod
    def from_hashes(cls, hashes: list[bytes] | list[Self]) -> Self:
        match hashes:
            case []:
                raise ValueError("Cannot compute merkle root of empty list")
            case [bytes(hash1)]:
                return cls(hash1)
            case [hash1, hash2]:
                return cls(cast(MerkleTreePair, (hash1, hash2)))
            case [*rest]:
                nodes = [
                    cls(cast(MerkleTreePair, pair))
                    for pair in zip_longest(rest[::2], rest[1::2], fillvalue=rest[-1])
                ]
                return cls.from_hashes(nodes)
