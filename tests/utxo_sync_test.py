import math
from datetime import UTC, datetime
from functools import cache
from io import BytesIO
from pathlib import Path
from typing import cast

import libarchive  # pyright:ignore[reportMissingTypeStubs]
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from coincidence.block.types import Block
from coincidence.transaction.types.common import varint
from coincidence.transaction.types.script import ScriptDeserializationFlag
from coincidence.transaction.types.transaction import Transaction
from coincidence.utxo.dao import insert_block, insert_transactions
from coincidence.utxo.schema import Base

# pyright: reportUnknownMemberType=false, reportPrivateLocalImportUsage=false


@pytest.fixture(scope="module")
def database_session_factory(request: pytest.FixtureRequest):
    engine = create_engine("sqlite:///:memory:")
    timestamp = datetime.now(UTC).astimezone().isoformat(timespec="seconds")
    save_file_path = (
        Path(__file__).parent
        / ".databases"
        / f"{request.module.__name__}-{timestamp}.db"
    )
    save_file_path.parent.mkdir(parents=True, exist_ok=True)
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
    with engine.connect() as connection:
        _ = connection.execute(text("PRAGMA foreign_keys = ON"))
        yield sessionmaker(bind=connection)
    # save the database to disk
    with engine.begin() as connection:
        _ = connection.execute(text("VACUUM INTO :path"), {"path": str(save_file_path)})
    engine.dispose()


@pytest.fixture
def database_session(database_session_factory: sessionmaker[Session]):
    with database_session_factory() as session, session.begin():
        yield session


@cache
def _read_fixtures_tar() -> dict[int, bytes]:
    fixture_file_contents: list[tuple[int, bytes]] = []
    with libarchive.file_reader(
        str(Path(__file__).parent / "fixtures.tar.lzma")
    ) as fixture_file:
        for entry in fixture_file:
            if not (
                entry.isfile
                and (path := Path(cast(str, entry.pathname))).suffix == ".hex"
            ):
                continue
            height, data = int(path.stem), bytearray()
            for block in entry.get_blocks():
                data += block
            fixture_file_contents += [(height, bytes.fromhex(data.decode()))]
    return dict(sorted(fixture_file_contents))


TOTAL_SECTIONS = 1000
planned_height_sections: list[tuple[int, int]] = []


@pytest.fixture
def utxo_data_at_height(request: pytest.FixtureRequest, pytestconfig: pytest.Config):
    fixture_file_contents = _read_fixtures_tar()
    if not planned_height_sections:
        final_height = cast(int, pytestconfig.getoption("--utxo-sync-height"))
        if final_height < 0:
            final_height = max(fixture_file_contents)
        assert final_height >= TOTAL_SECTIONS
        each_in_section = math.ceil(final_height / TOTAL_SECTIONS)
        planned_height_sections.extend(
            [
                (start, min(start + each_in_section, final_height))
                for start in range(0, final_height, each_in_section)
            ]
        )
    start, end = planned_height_sections[cast(int, request.param)]
    return {height: fixture_file_contents[height] for height in range(start, end)}


@pytest.mark.parametrize("utxo_data_at_height", range(TOTAL_SECTIONS), indirect=True)
def test_utxo_sync(
    database_session: Session,
    utxo_data_at_height: dict[int, bytes],
):
    for height, data in utxo_data_at_height.items():
        reader = BytesIO(data)
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
        with database_session.begin_nested():
            _ = insert_block(database_session, height, block)
            _ = insert_transactions(database_session, block.hash, transactions)
