import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from loguru import logger
from util import config
from util.config import _Config

logger.disable("util")

dummy_json: dict = {
    "key_1": "value",
    "key_2": True
}


@pytest.fixture
def dummy_config_file() -> Path:
    with NamedTemporaryFile("r") as tmp_file:
        tmp_config: Path = Path(tmp_file.name)
        tmp_config.write_text(json.dumps(dummy_json))
        yield tmp_config


def test_config_not_loaded_yet():
    _Config.config = None
    with pytest.raises(ValueError):
        config.config()


def test_config_initial_load(dummy_config_file):
    cfg = config.config(dummy_config_file)
    for key, value in dummy_json.items():
        assert cfg[key] == value


def test_config_cached_retrieval(dummy_config_file):
    _ = config.config(dummy_config_file)
    # config should now be cached
    cfg = config.config()
    for key, value in dummy_json.items():
        assert cfg[key] == value

