import json
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

import pytest
from loguru import logger
from util.time_anchor import TimeAnchor

# disable logging for util module to not spam log files and stderr
logger.disable("util")


unix_zero_iso_timestamp = datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

test_file_contents = json.dumps(
    {
        "sync_nvd": "1970-01-01T00:00:00.000+00:00",
        "rebuild_nvd": "1970-01-01T00:00:00.000+00:00",
        "release_git_package": "1970-01-01T00:00:00.000+00:00",
        "update_git_repo": "1970-01-01T00:00:00.000+00:00",
    },
    indent=2,
)


@pytest.fixture
def temp_file():
    with NamedTemporaryFile("w") as tmp:
        tmp.write(test_file_contents)
        tmp.flush()
        yield Path(tmp.name)


@pytest.fixture
def example_anchor(temp_file):
    yield TimeAnchor(temp_file)


def test_init_file_exists(temp_file):
    anchor = TimeAnchor(temp_file)
    assert anchor.sync_nvd == unix_zero_iso_timestamp


def test_init_file_does_not_exist():
    with TemporaryDirectory() as tmp:
        tmp_file = Path(tmp) / "nested" / "dir" / "structure" / "anchors.json"
        assert not tmp_file.exists()

        anchor = TimeAnchor(tmp_file)

        assert tmp_file.exists()
        assert tmp_file.read_text() == test_file_contents
        assert anchor.sync_nvd == unix_zero_iso_timestamp


def test_get_anchor_known(example_anchor):
    assert example_anchor.get_anchor("release_git_package") == unix_zero_iso_timestamp


def test_get_anchor_unknown(example_anchor):
    with pytest.raises(AttributeError):
        example_anchor.get_anchor("does_not_exist")


def test_set_anchor_known(example_anchor):
    plus_three_seconds = unix_zero_iso_timestamp + timedelta(seconds=3)
    example_anchor.set_anchor("release_git_package", plus_three_seconds)
    assert example_anchor.get_anchor("release_git_package") == plus_three_seconds


def test_set_anchor_unknown(example_anchor):
    with pytest.raises(AttributeError):
        example_anchor.set_anchor("does_not_exist", "does not work")


def test_getters(example_anchor):
    assert example_anchor.sync_nvd == unix_zero_iso_timestamp
    assert example_anchor.update_git_repo == unix_zero_iso_timestamp
    assert example_anchor.release_git_package == unix_zero_iso_timestamp
    assert example_anchor.rebuild_nvd == unix_zero_iso_timestamp


def test_setters_and_fs_persistence(example_anchor):
    example_anchor.sync_nvd = unix_zero_iso_timestamp + timedelta(seconds=1)
    example_anchor.update_git_repo = unix_zero_iso_timestamp + timedelta(seconds=2)
    example_anchor.release_git_package = unix_zero_iso_timestamp + timedelta(seconds=3)
    example_anchor.rebuild_nvd = unix_zero_iso_timestamp + timedelta(seconds=4)
    assert example_anchor.sync_nvd == unix_zero_iso_timestamp + timedelta(seconds=1)
    assert example_anchor.update_git_repo == unix_zero_iso_timestamp + timedelta(seconds=2)
    assert example_anchor.release_git_package == unix_zero_iso_timestamp + timedelta(seconds=3)
    assert example_anchor.rebuild_nvd == unix_zero_iso_timestamp + timedelta(seconds=4)
