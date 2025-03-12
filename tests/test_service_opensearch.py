import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Generator
from unittest.mock import Mock

import pytest
from loguru import logger
from openmock import openmock
from service.opensearch import NVDOpenSearch
from util.config import config

logger.disable("util")
logger.disable("service")


TEST_CVE_HEARTBLEED = json.loads((Path(__file__).parent / "assets/CVE-2014-0160.json").read_text())


@pytest.fixture
def patch_opensearch(monkeypatch) -> None:
    # indices are only partially implemented by openmock
    monkeypatch.setattr("service.opensearch.NVDOpenSearch.index_is_blocked", Mock(return_value=False))


@pytest.fixture
def opensearch_config_file() -> Generator:
    opensearch_config = {
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
        }
    }
    with NamedTemporaryFile("r") as tmp_file:
        tmp_config: Path = Path(tmp_file.name)
        tmp_config.write_text(json.dumps(opensearch_config))
        yield config(tmp_config)


@openmock
def test_connection_no_index_creation(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch(create_index=False) as client:
        client._os.index("cve", body={"empty": "document"})


@openmock
def test_connection_index_creation(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch(create_index=True) as client:
        client._os.index("cve", body={"empty": "document"})


@openmock
def test_insert_and_update_cve(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        client.update_cve(TEST_CVE_HEARTBLEED)

        returned: dict = client._os.get("cve", TEST_CVE_HEARTBLEED["cve"]["id"])["_source"]
        assert returned == TEST_CVE_HEARTBLEED

        updated_heartbleed = copy.deepcopy(TEST_CVE_HEARTBLEED)
        updated_heartbleed["cve"]["lastModified"] = "2050-12-31T23:59:59.999+00:00"
        client.update_cve(updated_heartbleed)

        returned = client._os.get("cve", updated_heartbleed["cve"]["id"])["_source"]
        assert returned == updated_heartbleed


@openmock
def test_get_cve_by_id(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        client.update_cve(TEST_CVE_HEARTBLEED)
        assert TEST_CVE_HEARTBLEED == client.get_cve_by_id(TEST_CVE_HEARTBLEED["cve"]["id"])


@openmock
def test_get_last_modified_cve_success(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        last_modified_cve = copy.deepcopy(TEST_CVE_HEARTBLEED)
        last_modified_cve["cve"]["id"] = "CVE-2014-123456789"
        last_modified_cve["cve"]["lastModified"] = "2050-12-31T23:59:59.999"

        expected_datetime: datetime = datetime.fromisoformat("2050-12-31T23:59:59.999+00:00")

        client.update_cve(last_modified_cve)
        client.update_cve(TEST_CVE_HEARTBLEED)

        assert client.get_last_mod_cve() == (last_modified_cve, expected_datetime)


@openmock
def test_get_last_modified_cve_failure(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        assert client.get_last_mod_cve() == (None, datetime.fromisoformat("1970-01-01T00:00:00.000+00:00"))


@openmock
def test_get_last_published_cve_success(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        last_published_cve: dict = copy.deepcopy(TEST_CVE_HEARTBLEED)
        last_published_cve["cve"]["id"] = "CVE-2014-123456789"
        last_published_cve["cve"]["published"] = "2050-12-31T23:59:59.999"

        expected_datetime: datetime = datetime.fromisoformat("2050-12-31T23:59:59.999+00:00")

        client.update_cve(last_published_cve)
        client.update_cve(TEST_CVE_HEARTBLEED)

        assert client.get_last_published_cve() == (last_published_cve, expected_datetime)


@openmock
def test_get_last_published_cve_failure(opensearch_config_file, patch_opensearch):
    with NVDOpenSearch() as client:
        assert client.get_last_published_cve() == (None, datetime.fromisoformat("1970-01-01T00:00:00.000+00:00"))


@openmock
def test_bulk_update_cves(opensearch_config_file, patch_opensearch):
    cves: list = []

    for i in range(0, 100):
        dummy: dict = copy.deepcopy(TEST_CVE_HEARTBLEED)
        dummy["cve"]["id"] = f"CVE-2014-{i}"
        cves += [dummy]

    with NVDOpenSearch() as client:
        client.bulk_update_cves(cves)

        for cve in cves:
            result: dict = client.get_cve_by_id(cve["cve"]["id"])
            assert result == cve


@openmock
def test_get_cves_by_published_range(opensearch_config_file, patch_opensearch):
    cves: list = []

    for i in range(0, 20):
        dummy: dict = copy.deepcopy(TEST_CVE_HEARTBLEED)
        dummy["cve"]["id"] = f"CVE-2014-{i}"
        dummy["cve"]["published"] = (datetime.fromisoformat("1970-01-01T00:00:00.000") + timedelta(days=i)).isoformat()
        cves += [dummy]

    with NVDOpenSearch() as client:
        client.bulk_update_cves(cves)

        for i, cve in enumerate(cves):
            start: datetime = datetime.fromisoformat("1970-01-01T00:00:00.000")
            stop: datetime = datetime.fromisoformat(cve["cve"]["published"])
            results: list[dict] = list(client.get_cves_by_published_range(start, stop))
            assert len(results) == i + 1

            for j in range(0, i + 1):
                assert results[i] == cves[i]


@openmock
def test_get_cves_by_modified_range(opensearch_config_file, patch_opensearch):
    cves: list = []

    for i in range(0, 20):
        dummy: dict = copy.deepcopy(TEST_CVE_HEARTBLEED)
        dummy["cve"]["id"] = f"CVE-2014-{i}"
        dummy["cve"]["lastModified"] = (
            datetime.fromisoformat("1970-01-01T00:00:00.000") + timedelta(days=i)
        ).isoformat()
        cves += [dummy]

    with NVDOpenSearch() as client:
        client.bulk_update_cves(cves)

        for i, cve in enumerate(cves):
            start: datetime = datetime.fromisoformat("1970-01-01T00:00:00.000")
            stop: datetime = datetime.fromisoformat(cve["cve"]["lastModified"])
            results: list[dict] = list(client.get_cves_by_mod_range(start, stop))
            assert len(results) == i + 1

            for j in range(0, i + 1):
                assert results[i] == cves[i]
