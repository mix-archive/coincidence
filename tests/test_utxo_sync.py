import shutil
from io import BytesIO
from pathlib import Path
from tarfile import TarFile
from tempfile import NamedTemporaryFile

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from coincidence.block.types import Block
from coincidence.transaction.types.common import varint
from coincidence.transaction.types.script import ScriptDeserializationFlag
from coincidence.transaction.types.transaction import Transaction
from coincidence.utxo.dao import (
    insert_block,
    insert_transactions,
)
from coincidence.utxo.schema import (
    Base,
)

fixture_file = TarFile.open(Path(__file__).parent / "fixtures.tar.lzma", "r")


@pytest.fixture(scope="session")
def database_session_factory():
    with NamedTemporaryFile(suffix=".db") as file:
        path = Path(file.name)
        engine = create_engine(f"sqlite:///{path}")
        with engine.begin() as connection:
            Base.metadata.create_all(connection)
        with engine.connect() as connection:
            _ = connection.execute(text("PRAGMA foreign_keys = ON"))
            yield sessionmaker(bind=connection)
        # save the database to disk
        with engine.begin() as connection:
            _ = connection.execute(text("VACUUM"))
        # load the database from disk
        save_file_path = Path(__file__).parent / "db.sqlite3"
        save_file_path.unlink(missing_ok=True)
        shutil.copy(path, save_file_path)


def test_utxo_sync(database_session_factory: sessionmaker[Session]):
    for height, member in sorted(
        (int(Path(member.name).stem), member)
        for member in fixture_file.getmembers()
        if member.isfile() and member.name.endswith(".hex")
    )[:10000]:
        file = fixture_file.extractfile(member)
        assert file is not None
        reader = BytesIO(bytes.fromhex(file.read().decode()))
        block = Block.deserialize(reader)
        transactions = [
            Transaction.deserialize(
                reader,
                (
                    ScriptDeserializationFlag.FROM_COINBASE
                    if index == 0
                    else ScriptDeserializationFlag(0)
                ),
            )
            for index in range(varint.deserialize(reader))
        ]

        with database_session_factory() as session, session.begin():
            block_obj = insert_block(session, height, block)
            _ = insert_transactions(session, block_obj, transactions)
