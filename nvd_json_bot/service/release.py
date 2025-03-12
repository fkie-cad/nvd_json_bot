from __future__ import annotations

import json
import lzma
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import github
from github import GitRelease
from loguru import logger
from util.config import config


class FeedRelease:
    def __init__(self) -> None:
        self._settings: dict = config()["github"]
        logger.debug(f"creating new github release using settings: {self._settings}")
        self._temp_dir: TemporaryDirectory
        self._github: github.Github = github.Github(self._settings["personal_access_token"])
        self._repo = self._github.get_repo(self._settings["remote_repository"])

    def __enter__(self) -> FeedRelease:
        self._temp_dir = TemporaryDirectory()
        logger.debug(f"tempdir for feed release creation is '{self._temp_dir.name}'")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._temp_dir is not None:
            self._temp_dir.__exit__(exc_type, exc_val, exc_tb)

    def create_feed_json_xz(self, feed_name: str, cve_items: list[dict], timestamp: datetime) -> None:
        if self._temp_dir is None:
            raise FileNotFoundError("no tempdir created, use __enter__/__exit__")

        obj: dict = {
            "timestamp": timestamp.isoformat(timespec="seconds"),
            "cve_count": len(cve_items),
            "feed_name": feed_name,
            "source": self._settings["remote_repository"],
            "cve_items": sorted(cve_items, key=lambda cve: cve["id"]),
        }

        raw: bytes
        compressed: bytes
        raw, compressed = self._compress_json_object(obj, f"{feed_name}.json.xz")
        self._create_meta_file(obj, f"{feed_name}.meta", raw, compressed)

        obj["cve_items"] = f"[...] ({len(obj['cve_items'])} items)"
        logger.info(f"wrote and compressed {feed_name}.json.xz. contents: {obj}")

    def _compress_json_object(self, obj: dict, file_name: str) -> tuple[bytes, bytes]:
        compressor = lzma.LZMACompressor(preset=self._settings["lzma_compression_level"])

        raw: bytes = json.dumps(obj, indent=2).encode()

        compressed: bytes = compressor.compress(raw)
        compressed += compressor.flush()

        destination_path: Path = self._temp_dir.name / Path(file_name)
        destination_path.write_bytes(compressed)
        logger.debug(f"wrote {len(compressed)} compressed bytes to {str(destination_path)}")

        return raw, compressed

    def _create_meta_file(self, obj: dict, file_name: str, raw: bytes, compressed: bytes) -> None:
        latest_mod: datetime = datetime.fromisoformat("1970-01-01T00:00:00")

        for cve in obj["cve_items"]:
            curr: datetime = datetime.fromisoformat(cve["lastModified"])
            if curr < latest_mod:
                continue
            latest_mod = curr

        hash_digest: str = sha256(raw).hexdigest()

        meta: str = (
            f"lastModifiedDate:{latest_mod.isoformat(timespec='seconds')}+00:00\nsize:{len(raw)}\nxzSize:{len(compressed)}\nsha256:{hash_digest}"
        )
        destination_path: Path = self._temp_dir.name / Path(file_name)
        destination_path.write_text(meta)
        logger.debug(f"wrote {len(meta)} bytes of meta file to {str(destination_path)}")

    def publish(self, timestamp: datetime) -> tuple[str, str]:
        release_version: str = timestamp.strftime("v%Y.%m.%d-%H%M%S")
        obj: str = self._repo.get_branch(self._settings["branch"]).commit.sha

        release_data: dict[str, Any] = {
            "tag": release_version,
            "tag_message": f"Feed Release: {timestamp.isoformat(timespec='seconds')}",
            "release_name": release_version,
            "release_message": f"Feed Release: {timestamp.isoformat(timespec='seconds')}",
            "type": "lightweight",
            "object": obj,
        }

        logger.info(f"creating release {release_data} ...")
        self._repo.create_git_tag_and_release(**release_data)

        gh_release = self._repo.get_release(release_version)
        for asset in Path(self._temp_dir.name).glob("*.json.xz"):
            logger.info(f"uploading release feed {asset}")
            gh_release.upload_asset(path=str(asset))

        for meta in Path(self._temp_dir.name).glob("*.meta"):
            logger.info(f"uploading meta file {meta}")
            gh_release.upload_asset(path=str(meta))

        return release_version, obj

    def prune_old(self) -> None:
        logger.info(f"start release pruning")
        latest: GitRelease.GitRelease = self._repo.get_latest_release()
        for gh_release in self._repo.get_releases():
            if gh_release == latest:
                continue
            logger.info(f"pruning old release {gh_release.tag_name} from {gh_release.created_at}")
            gh_release.delete_release()
