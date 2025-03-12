import json
from datetime import datetime
from pathlib import Path

from loguru import logger


class TimeAnchor:
    def __init__(self, json_path: Path | str) -> None:
        self._path: Path = Path(json_path)
        if not self._path.exists():
            self._create_defaults()

        logger.debug(f"loading time anchors json from '{json_path}'")

        self._anchors: dict[str, str] = json.loads(self._path.read_text())

    def _create_defaults(self) -> None:
        logger.warning(
            f"the time anchors json file '{str(self._path)}' does not exist! creating with unix timestamps = 0.."
        )
        self._path.parent.mkdir(exist_ok=True, parents=True)

        skeleton: dict[str, str] = {
            "sync_nvd": "1970-01-01T00:00:00.000+00:00",
            "rebuild_nvd": "1970-01-01T00:00:00.000+00:00",
            "release_git_package": "1970-01-01T00:00:00.000+00:00",
            "update_git_repo": "1970-01-01T00:00:00.000+00:00",
        }

        logger.debug(f"writing skeleton to '{str(self._path)}': {skeleton}")
        self._path.write_text(json.dumps(skeleton, indent=2))

    @property
    def rebuild_nvd(self) -> datetime:
        return self.get_anchor("rebuild_nvd")

    @rebuild_nvd.setter
    def rebuild_nvd(self, value: str | datetime):
        self.set_anchor("rebuild_nvd", value)

    @property
    def sync_nvd(self) -> datetime:
        return self.get_anchor("sync_nvd")

    @sync_nvd.setter
    def sync_nvd(self, value: str | datetime):
        self.set_anchor("sync_nvd", value)

    @property
    def update_git_repo(self) -> datetime:
        return self.get_anchor("update_git_repo")

    @update_git_repo.setter
    def update_git_repo(self, value: str | datetime):
        self.set_anchor("update_git_repo", value)

    @property
    def release_git_package(self) -> datetime:
        return self.get_anchor("release_git_package")

    @release_git_package.setter
    def release_git_package(self, value: str | datetime):
        self.set_anchor("release_git_package", value)

    def get_anchor(self, name: str) -> datetime:
        try:
            return datetime.fromisoformat(self._anchors[name])
        except KeyError:
            msg: str = f"'{type(self).__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

    def set_anchor(self, name: str, value: str | datetime):
        try:
            if name not in self._anchors:
                raise KeyError
            iso_value: str = value.isoformat() if isinstance(value, datetime) else value
            self._anchors[name] = iso_value
            self.save()
        except (KeyError, ValueError):
            msg: str = f"'{type(self).__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

    def save(self):
        logger.debug(f"saving time anchors to '{str(self._path)}': {self._anchors}")
        self._path.write_text(json.dumps(self._anchors, indent=2))
