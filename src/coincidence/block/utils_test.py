import pytest

from coincidence.block.utils import MerkleTree, ProofPosition
from coincidence.crypto.utils import sha256

from .types_test import BlockData, all_block_data, block_ids


def test_empty_list():
    with pytest.raises(ValueError, match="Cannot compute merkle root of empty list"):
        _ = MerkleTree.from_hashes([])


@pytest.mark.parametrize("block_data", all_block_data, ids=block_ids)
def test_block_merkle_root(block_data: BlockData):
    hashes = [bytes.fromhex(tx)[::-1] for tx in block_data.tx]
    expected = bytes.fromhex(block_data.merkleroot)[::-1]

    assert MerkleTree.from_hashes(hashes).hash == expected


@pytest.mark.parametrize("block_data", all_block_data, ids=block_ids)
def test_block_merkle_proof(block_data: BlockData):
    hashes = [bytes.fromhex(tx)[::-1] for tx in block_data.tx]
    merkle_tree = MerkleTree.from_hashes(hashes)

    for tx in hashes:
        path = merkle_tree.proof(tx)
        assert path is not None
        hash_ = tx
        for sibling, pos in path:
            if pos is ProofPosition.LEFT:
                hash_ = sha256(sha256(sibling + hash_))
            else:
                hash_ = sha256(sha256(hash_ + sibling))
        assert hash_ == merkle_tree.hash, tx

    for tx in hashes:
        path = merkle_tree.proof(tx[::-1])
        assert path is None

    for tx in hashes:
        path = merkle_tree.proof(tx + b"\x00")
        assert path is None

    for tx in hashes:
        path = merkle_tree.proof(b"\x00" + tx)
        assert path is None

    for tx in hashes:
        path = merkle_tree.proof(b"\x00" + tx + b"\x00")
        assert path is None
