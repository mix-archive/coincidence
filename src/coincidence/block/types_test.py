import json
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from coincidence.block.types import Block

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@dataclass
class BlockData:
    hash: str
    confirmations: int
    height: int
    version: int
    versionHex: str  # noqa: N815
    merkleroot: str
    time: int
    mediantime: int
    nonce: int
    bits: str
    difficulty: float
    chainwork: str
    nTx: int  # noqa: N815
    previousblockhash: str
    nextblockhash: str
    strippedsize: int
    size: int
    weight: int
    tx: list[str]


block_ids: list[str] = []
all_block_data: list[BlockData] = []
all_block_binary: list[bytes] = []

for block_file in FIXTURES_DIR.glob("*.json"):
    block_ids.append(block_file.stem)
    with block_file.open("r") as f:
        loaded: dict[str, Any] = json.load(f)  # pyright:ignore[reportExplicitAny]
    all_block_data.append(BlockData(**loaded))  # pyright:ignore[reportAny]
    with block_file.with_suffix(".hex").open("r") as f:
        all_block_binary.append(bytes.fromhex(f.read()))


@pytest.mark.parametrize(
    ("block_data", "binary"),
    [*zip(all_block_data, all_block_binary, strict=True)],
    ids=block_ids,
)
def test_block_header(block_data: BlockData, binary: bytes) -> None:
    block = Block.deserialize(BytesIO(binary))

    assert block.version == block_data.version
    assert block.previous_block == bytes.fromhex(block_data.previousblockhash)[::-1]
    assert block.merkle_root == bytes.fromhex(block_data.merkleroot)[::-1]
    assert block.timestamp == block_data.time
    assert block.bits == int(block_data.bits, 16)

    assert id(block.features)
    assert block.hash == bytes.fromhex(block_data.hash)
    assert block.hash < block.target

    assert binary.startswith(block.serialize())
