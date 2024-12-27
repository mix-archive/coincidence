from pathlib import Path

import pytest
from pyinstrument import Profiler

PROFILE_ROOT = Path(__file__).parent / ".profiles"
PROFILE_ROOT.mkdir(exist_ok=True, parents=True)

FIXTURE_FILE = Path(__file__).parent / "tests" / "fixtures.tar.lzma"


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--utxo-sync-height",
        type=int,
        default=10000,
        help="The height of the block to utxo sync",
    )
    parser.addoption(
        "--enable-profiler",
        action="store_true",
        help="Enable the profiler for all tests",
    )


@pytest.fixture(autouse=True, scope="module")
def auto_profile(request: pytest.FixtureRequest, pytestconfig: pytest.Config):
    if not pytestconfig.getoption("--enable-profiler"):
        yield
        return
    # Turn profiling on
    with Profiler() as profiler:
        yield  # Run test
    results_file = PROFILE_ROOT / f"{request.module.__name__}.html"  # pyright:ignore[reportUnknownMemberType]
    profiler.write_html(results_file)
