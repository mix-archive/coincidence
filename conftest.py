from pathlib import Path

import pytest
from pyinstrument import Profiler

PROFILE_ROOT = Path(__file__).parent / ".profiles"
PROFILE_ROOT.mkdir(exist_ok=True, parents=True)


@pytest.fixture(autouse=True, scope="module")
def auto_profile(request: pytest.FixtureRequest):
    # Turn profiling on
    with Profiler() as profiler:
        yield  # Run test
    results_file = PROFILE_ROOT / f"{request.module.__name__}.html"  # pyright:ignore[reportUnknownMemberType]
    profiler.write_html(results_file)
