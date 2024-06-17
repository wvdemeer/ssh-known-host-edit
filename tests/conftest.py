import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="function")  # noqa: PT003
def known_hosts_filename():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_file = Path(tmp_dir) / 'known_hosts_test'
        yield str(tmp_file)
