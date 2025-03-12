import json
import time
from datetime import datetime, timezone
from typing import Generator

import requests
import util
from loguru import logger
from util.config import config


class NVDVulnerabilityAPI:
    def __init__(self) -> None:
        self._settings: dict = config()["nvd"]
        self._backoff: float = 30.0
        logger.debug(f"connecting to NVD Vulnerability API 2.0 using settings: {self._settings}")

    @staticmethod
    def _construct_query_params(start_index: int, modified_start: datetime | None = None) -> dict[str, str]:
        params: dict[str, str] = {"startIndex": str(start_index)}

        if modified_start is not None:
            params["lastModStartDate"] = modified_start.isoformat()
            params["lastModEndDate"] = datetime.now(timezone.utc).isoformat()

        logger.debug(f"query parameters for NVD Vulnerability API request: {params}")

        return params

    def poll_cve_updates(self, since: datetime | None = None) -> Generator[tuple[list[dict], int, int], None, None]:
        fetched: int = 0
        total: int = 1
        retries: int = 0
        headers: dict[str, str] = {}

        if self._settings["api_key"] is not None and self._settings["api_key"] != "":
            headers["apiKey"] = self._settings["api_key"]
            logger.debug(f"using api_key as request header since defined in config: {headers}")

        while fetched < total:
            logger.debug(f"new request to NVD Vulnerability API endpoint: {self._settings['endpoint']}")

            params: dict[str, str] = self._construct_query_params(fetched, since)
            response: requests.Response = requests.get(
                self._settings["endpoint"], params=params, headers=headers, timeout=120
            )

            if response.status_code == 404:
                raise ConnectionError(
                    f"NVD Connection failed -- probably due to bad api key. status code: {response.status_code}, headers: {response.headers}"
                )

            if response.status_code != 200:
                if retries >= 3:
                    raise ConnectionError(
                        f"NVD Connection failed after {retries} retries. status code: {response.status_code}, headers: {response.headers}"
                    )
                logger.warning(
                    f"Connection to NVD failed. status code: {response.status_code}, headers: {response.headers}, retry: {retries}"
                )
                logger.warning(f"Backoff for {self._backoff} and retry...")
                time.sleep(self._backoff)
                retries += 1
                continue

            result: dict = json.loads(response.content.decode())

            total: int = result["totalResults"]
            cves: list = result["vulnerabilities"]

            logger.debug(f"retrieved {len(cves)} from NVD Vulnerability endpoint (status code: {response.status_code})")

            fetched += len(cves)
            util.throttle(self._settings["throttle_window_size"] / self._settings["throttle_window_request_limit"])

            yield cves, fetched, total
