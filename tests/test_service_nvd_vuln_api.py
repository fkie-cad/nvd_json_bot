import copy
import datetime
import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
import responses
from loguru import logger
from service.nvd_api import NVDVulnerabilityAPI
from util.config import config

logger.disable("util")
logger.disable("service")

NVD_RESPONSE = json.loads((Path(__file__).parent / "assets/nvd_response.json").read_text())
NVD_REQUEST_START_TIMESTAMP = datetime.datetime.fromisoformat("2021-08-04T13:00:00.000+00:00")
NVD_REQUEST_STOP_TIMESTAMP = datetime.datetime.fromisoformat("2021-08-04T15:00:00.000+00:00")


@pytest.fixture
def nvd_config_file() -> dict:
    nvd_config: dict = {
        "nvd": {
            "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "throttle_window_size": 3.0,
            "throttle_window_request_limit": 5.0,
            "api_key": "",
        }
    }
    with NamedTemporaryFile("r") as tmp_file:
        tmp_config = Path(tmp_file.name)
        tmp_config.write_text(json.dumps(nvd_config))
        yield config(tmp_config)


@responses.activate
def test_poll_cve_updates_good_new_no_key(nvd_config_file, monkeypatch):
    nvd: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    class FixedDatetime:
        @classmethod
        def now(cls):
            return NVD_REQUEST_STOP_TIMESTAMP

    monkeypatch.setattr("datetime.datetime", FixedDatetime)

    try:
        responses.add(responses.GET, nvd_config_file["nvd"]["endpoint"], json=NVD_RESPONSE, status=200)
        for cves, fetched, total in nvd.poll_cve_updates(since=NVD_REQUEST_START_TIMESTAMP):
            assert len(cves) == 4
            assert fetched == 4
            assert total == 4
    finally:
        responses.delete(responses.GET, nvd_config_file["nvd"], ["endpoint"])


@responses.activate
def test_poll_cve_updates_good_new_with_key(nvd_config_file, monkeypatch):
    nvd: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    nvd_config_file["nvd"]["api_key"] = "asd"

    class FixedDatetime:
        @classmethod
        def now(cls):
            return NVD_REQUEST_STOP_TIMESTAMP

    monkeypatch.setattr("datetime.datetime", FixedDatetime)

    try:
        responses.add(responses.GET, nvd_config_file["nvd"]["endpoint"], json=NVD_RESPONSE, status=200)
        for cves, fetched, total in nvd.poll_cve_updates(since=NVD_REQUEST_START_TIMESTAMP):
            assert len(cves) == 4
            assert fetched == 4
            assert total == 4
    finally:
        responses.delete(responses.GET, nvd_config_file["nvd"], ["endpoint"])


@responses.activate
def test_poll_cve_updates_bad_with_key(nvd_config_file, monkeypatch):
    nvd: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    nvd_config_file["nvd"]["api_key"] = "bad_key"

    class FixedDatetime:
        @classmethod
        def now(cls):
            return NVD_REQUEST_STOP_TIMESTAMP

    monkeypatch.setattr("datetime.datetime", FixedDatetime)

    try:
        responses.add(responses.GET, nvd_config_file["nvd"]["endpoint"], status=404)

        with pytest.raises(ConnectionError):
            for _ in nvd.poll_cve_updates(since=NVD_REQUEST_START_TIMESTAMP):
                pass
    finally:
        responses.delete(responses.GET, nvd_config_file["nvd"], ["endpoint"])


@responses.activate
def test_poll_cve_updates_good_empty(nvd_config_file, monkeypatch):
    nvd: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    class FixedDatetime:
        @classmethod
        def now(cls):
            return NVD_REQUEST_STOP_TIMESTAMP

    monkeypatch.setattr("datetime.datetime", FixedDatetime)

    faked_response: dict = copy.deepcopy(NVD_RESPONSE)

    faked_response["vulnerabilities"] = []
    faked_response["resultsPerPage"] = 0
    faked_response["totalResults"] = 0

    try:
        responses.add(responses.GET, nvd_config_file["nvd"]["endpoint"], json=faked_response, status=200)
        for cves, fetched, total in nvd.poll_cve_updates(since=NVD_REQUEST_START_TIMESTAMP):
            assert len(cves) == 0
            assert fetched == 0
            assert total == 0
    finally:
        responses.delete(responses.GET, nvd_config_file["nvd"], ["endpoint"])


@responses.activate
def test_poll_cve_updates_bad(nvd_config_file, monkeypatch):
    nvd: NVDVulnerabilityAPI = NVDVulnerabilityAPI()
    nvd._backoff = 0.5

    class FixedDatetime:
        @classmethod
        def now(cls):
            return NVD_REQUEST_STOP_TIMESTAMP

    monkeypatch.setattr("datetime.datetime", FixedDatetime)

    faked_response: dict = copy.deepcopy(NVD_RESPONSE)

    faked_response["vulnerabilities"] = []
    faked_response["resultsPerPage"] = 0
    faked_response["totalResults"] = 0

    try:
        responses.add(responses.GET, nvd_config_file["nvd"]["endpoint"], json=NVD_RESPONSE, status=500)
        with pytest.raises(ConnectionError):
            for _ in nvd.poll_cve_updates(since=NVD_REQUEST_START_TIMESTAMP):
                pass
    finally:
        responses.delete(responses.GET, nvd_config_file["nvd"], ["endpoint"])
