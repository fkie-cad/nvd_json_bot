import json
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Generator
from unittest.mock import Mock

import command
import pytest
import service
from loguru import logger
from openmock import openmock
from util.config import config

logger.disable("util")
logger.disable("service")
logger.disable("command")

test_file_contents = json.dumps(
    {
        "rebuild_nvd": "1970-01-01T00:00:00.000+00:00",
        "sync_nvd": "1970-01-01T00:00:00.000+00:00",
        "release_git_package": "1970-01-01T00:00:00.000+00:00",
        "update_git_repo": "1970-01-01T00:00:00.000+00:00",
    },
    indent=2,
)


@pytest.fixture
def temp_anchor_file():
    with NamedTemporaryFile("w") as tmp:
        tmp.write(test_file_contents)
        tmp.flush()
        yield Path(tmp.name)


@pytest.fixture
def config_file(temp_anchor_file) -> Generator:
    config_data: dict = {
        "time_anchors": {"path": str(temp_anchor_file)},
        "opensearch": {
            "host": "127.0.0.1",
            "port": 9200,
            "user": "admin",
            "password": "admin",
            "cve_index": "cve",
            "http_compress": True,
            "use_ssl": True,
            "verify_certs": False,
            "ssl_show_warn": False,
            "ssl_assert_hostname": False,
            "scroll_timeout": "30s",
            "scroll_size": 1,
        },
        "teams": {
            "connector_url": "",
            "enabled": False,
        },
    }
    with NamedTemporaryFile("r") as tmp_file:
        tmp_config = Path(tmp_file.name)
        tmp_config.write_text(json.dumps(config_data))
        yield config(tmp_config)


@pytest.fixture
def patch_opensearch(monkeypatch) -> None:
    # indices are only partially implemented by openmock
    monkeypatch.setattr("service.opensearch.NVDOpenSearch.index_is_blocked", Mock(return_value=False))


@openmock
def test_execute(monkeypatch, config_file, patch_opensearch):

    mock_exec: Mock = Mock(return_value=(datetime.fromisoformat("1970-01-02T00:00:00.000+00:00"), None))

    monkeypatch.setattr(
        "command.cmd_execute.__commands__",
        {
            "rebuild_nvd": mock_exec,
            "sync_nvd": mock_exec,
            "release_git_package": mock_exec,
            "update_git_repo": mock_exec,
        },
    )

    for cmd in ["sync_nvd", "rebuild_nvd", "release_git_package", "update_git_repo"]:
        command.execute(cmd)
        mock_exec.assert_called()
        mock_exec.reset_mock()
