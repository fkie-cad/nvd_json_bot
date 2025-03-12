from __future__ import annotations

import json
from contextlib import suppress
from datetime import datetime
from typing import Generator

import opensearchpy
from loguru import logger
from opensearchpy.exceptions import AuthorizationException, NotFoundError
from util.config import config


class NVDOpenSearch:
    def __init__(self, create_index: bool = True, index_overwrite: str = "") -> None:
        self._settings: dict = config()["opensearch"].copy()

        if index_overwrite:
            self._settings["cve_index"] = index_overwrite

        logger.debug(f"connecting to opensearch instance using settings: {self._settings}")
        self._os: opensearchpy.OpenSearch = opensearchpy.OpenSearch(
            hosts=[{"host": self._settings["host"], "port": self._settings["port"]}],
            http_compress=self._settings["http_compress"],
            http_auth=(self._settings["user"], self._settings["password"]),
            use_ssl=self._settings["use_ssl"],
            verify_certs=self._settings["verify_certs"],
            ssl_show_warn=self._settings["ssl_show_warn"],
            ssl_assert_hostname=self._settings["ssl_assert_hostname"],
            timeout=360,
        )
        if create_index:
            self.create_index_if_not_exists()

    def index_is_blocked(self) -> bool:
        try:
            settings: dict = self._os.indices.get_settings(self._settings["cve_index"])
            index_state: str = (
                settings.get(self._settings["cve_index"], {})
                .get("settings", {})
                .get("index", {})
                .get("blocks", {})
                .get("read", "false")
            )

            logger.debug(f"index blocking state of '{self._settings['cve_index']}' is: '{index_state}'")
            return index_state == "true"
        except AuthorizationException:
            return True
        except NotFoundError:
            return False

    def block_index(self) -> None:
        self._os.indices.put_settings(index=self._settings["cve_index"], body={"index.blocks.read": "true"})

    def unblock_index(self) -> None:
        self._os.indices.put_settings(index=self._settings["cve_index"], body={"index.blocks.read": "false"})

    def snapshot_index(self) -> None:
        repo: str = f"{self._settings['cve_index']}-snapshots"
        timestamp: str = str(datetime.now().timestamp()).split(".")[0]

        self._os.snapshot.create_repository(
            repo, body={"type": "fs", "settings": {"location": f"/usr/share/opensearch/data/snapshots/{repo}"}}
        )
        logger.debug(
            f"creating snapshot '{timestamp}' for index '{self._settings['cve_index']}' in repository '{repo}'"
        )
        self._os.snapshot.create(
            repository=repo,
            snapshot=timestamp,
            body={"indices": self._settings["cve_index"]},
            params={
                "wait_for_completion": "true",
            },
        )
        self._os.snapshot.cleanup_repository(repo)

    def restore_snapshot_index(self) -> None:
        repo: str = f"{self._settings['cve_index']}-snapshots"
        snapshots: dict = self._os.snapshot.get(repo, "*")

        # find latest snapshot
        latest: int = 0
        for snap in snapshots["snapshots"]:
            if not self._settings["cve_index"] in snap["indices"]:
                continue
            current: int
            try:
                current = int(snap["snapshot"])
            except ValueError:
                current = 0

            if current > latest:
                latest = current

        logger.debug(f"restoring snapshot '{latest}' for index '{self._settings['cve_index']}' in repository '{repo}'")
        self.unblock_index()
        self._os.indices.close(self._settings["cve_index"])
        self._os.snapshot.restore(
            repository=repo,
            snapshot=str(latest),
            body={"indices": self._settings["cve_index"]},
            params={"wait_for_completion": "true"},
        )
        self.unblock_index()
        self._os.indices.open(self._settings["cve_index"])
        self.block_index()

    def wipe_index(self) -> None:
        self.unblock_index()
        self._os.indices.close(self._settings["cve_index"])
        self._os.indices.delete(self._settings["cve_index"])
        logger.debug(f"removed index {self._settings['cve_index']} for recreation")
        self.create_index_if_not_exists()
        self.block_index()

    def create_index_if_not_exists(self) -> None:
        index: str = self._settings["cve_index"]

        if self.index_is_blocked():
            return

        with suppress(opensearchpy.exceptions.RequestError):
            self._os.indices.create(index)
            logger.info(f"created opensearch index '{index}'")

    def update_cve(self, cve: dict) -> None:
        logger.info(f"pushing single item {cve['cve']['id']} to opensearch")
        logger.debug(f"overwriting or indexing CVE: {cve}")
        self._os.index(self._settings["cve_index"], body=cve, id=cve["cve"]["id"])

    def _bulk_update_payload_constructor(self, cves: list[dict]) -> str:
        payload_string: str = ""

        for item in cves:
            action: dict = {"index": {"_index": self._settings["cve_index"], "_id": item["cve"]["id"]}}
            payload_string += json.dumps(action) + "\n"
            payload_string += json.dumps(item) + "\n"
        return payload_string

    def bulk_update_cves(self, cves: list[dict]) -> None:
        self._os.bulk(
            body=self._bulk_update_payload_constructor(cves),
            index=self._settings["cve_index"],
            refresh="wait_for",  # pyright: ignore[reportCallIssue]
        )

    def get_cve_by_id(self, cve_id: str) -> dict | None:
        logger.info(f"requesting single item {cve_id} from opensearch")
        result: dict = self._os.get("cve", cve_id)["_source"]
        logger.debug(f"single item result: {result}")

        return result

    def get_last_mod_cve(self) -> tuple[dict | None, datetime]:
        with suppress(IndexError, opensearchpy.exceptions.RequestError):
            return self._get_last_cve_by_date_field("lastModified")
        return None, datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

    def get_last_published_cve(self) -> tuple[dict | None, datetime]:
        with suppress(IndexError, opensearchpy.exceptions.RequestError):
            return self._get_last_cve_by_date_field("published")
        return None, datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

    def get_cves_by_published_range(
        self, start: datetime, stop: datetime, sort_field: str = "_id", sort: str = "asc"
    ) -> Generator[dict, None, None]:
        yield from self._get_cves_by_date_field_range("published", start, stop, sort_field, sort)

    def get_cves_by_mod_range(
        self, start: datetime, stop: datetime, sort_field: str = "_id", sort: str = "asc"
    ) -> Generator[dict, None, None]:
        yield from self._get_cves_by_date_field_range("lastModified", start, stop, sort_field, sort)

    def count_cves_within_date_range(self, date_field: str, start: datetime, stop: datetime) -> int:
        query: dict = {
            "query": {
                "range": {
                    f"cve.{date_field}": {
                        "gte": start.isoformat(),
                        "lte": stop.isoformat(),
                    }
                },
            }
        }
        return self._os.count(index=self._settings["cve_index"], body=query)["count"]

    def get_cves_by_year_within_mod_range(
        self, year: int, start: datetime, stop: datetime, sort: str = "asc"
    ) -> Generator[dict, None, None]:
        # NOTE: this query is not testable because match_phrase_prefix is not implemented in openmock
        query: dict = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase_prefix": {"cve.id": f"CVE-{year}"}},
                        {
                            "range": {
                                "cve.lastModified": {
                                    "gte": start.isoformat(),
                                    "lte": stop.isoformat(),
                                }
                            }
                        },
                    ],
                }
            },
            "sort": [{"cve.lastModified": {"order": sort}}],
        }

        yield from self._scroll_bulk_cve_fetch(query)

    def _get_cves_by_date_field_range(
        self, date_field: str, start: datetime, stop: datetime, sort_field: str = "_id", sort: str = "asc"
    ) -> Generator[dict, None, None]:
        query: dict = {
            "query": {
                "range": {
                    f"cve.{date_field}": {
                        "gte": start.isoformat(),
                        "lte": stop.isoformat(),
                    }
                },
            },
            "sort": [{sort_field: {"order": sort}}],
        }
        yield from self._scroll_bulk_cve_fetch(query)

    def _scroll_bulk_cve_fetch(self, query: dict) -> Generator[dict, None, None]:
        # Scroll API
        # https://opensearch.org/docs/latest/api-reference/scroll/
        scroll_id: str | None = None

        while True:
            if scroll_id is None:
                result = self._os.search(
                    index=self._settings["cve_index"],
                    body=query,
                    size=self._settings["scroll_size"],  # pyright: ignore[reportCallIssue]
                    scroll=self._settings["scroll_timeout"],  # pyright: ignore[reportCallIssue]
                )
            else:
                result = self._os.scroll(
                    scroll_id=scroll_id, scroll=self._settings["scroll_timeout"]  # pyright: ignore[reportCallIssue]
                )

            # OpenSearch might (but is not required to) assign a new scroll ID.
            # Once it provides a new ID, we have to query the results using said ID
            if "_scroll_id" in result:
                scroll_id = result["_scroll_id"]

            if not result["hits"]["hits"]:
                break

            # yield the CVE source documents one by one until the scroll results are processed
            for cve in result["hits"]["hits"]:
                yield cve["_source"]

    def _get_last_cve_by_date_field(self, date_field: str) -> tuple[dict | None, datetime]:
        query: dict = {"sort": [{f"cve.{date_field}": {"order": "desc"}}]}

        try:
            logger.debug(f"querying last CVE by date field '{date_field}' from opensearch")
            result: dict = self._os.search(
                index=self._settings["cve_index"], size=1, body=query  # pyright: ignore[reportCallIssue]
            )

            cve: dict = result["hits"]["hits"][0]["_source"]

            if cve["cve"][date_field][-6] != "+":
                # no timezone, add UTC
                cve["cve"][date_field] += "+00:00"
            timestamp: datetime = datetime.fromisoformat(cve["cve"][date_field])

            logger.debug(f"retrieved last '{date_field}' CVE = {cve}")
            return cve, timestamp
        except (IndexError, opensearchpy.exceptions.RequestError):
            logger.exception(
                f"could not obtain last '{date_field}' CVE because the result set is empty (this is fine when opensearch was not yet seeded with CVE data)"
            )
        return None, datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

    def __enter__(self) -> NVDOpenSearch:
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()

    def close(self):
        logger.debug(f"closing opensearch client connection")
        self._os.close()
