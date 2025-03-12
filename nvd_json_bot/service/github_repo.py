import csv
import json
import operator
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import jinja2
import util
from git.objects.commit import Commit
from git.repo import Repo
from loguru import logger
from service.opensearch import NVDOpenSearch
from util.config import config
from util.time_anchor import TimeAnchor


@dataclass
class RepoCacheDelta:
    id: str
    cve: dict
    changed: bool
    new: bool
    fs_hash: str
    cache_hash: str
    fs_last_modified: datetime
    cache_last_modified: datetime


class GithubRepo:
    def __init__(self, nvd_opensearch: "NVDOpenSearch", time_anchors: TimeAnchor) -> None:
        self._settings: dict = config()["github"]
        logger.debug(f"initializing github repo using settings: {self._settings}")
        self._nos: NVDOpenSearch = nvd_opensearch
        self._time_anchors: TimeAnchor = time_anchors
        self.repo: Repo = self._prepare_local_repo_copy()

    def _prepare_local_repo_copy(self) -> Repo:
        abs_deploy_key_path: Path = Path(self._settings["deploy_key_path"]).absolute()

        if not abs_deploy_key_path.exists() and self._settings["clone_type"] == "ssh":
            raise FileNotFoundError(f"could not find deploy_key_path '{abs_deploy_key_path}'")

        repo: Repo

        if Path(self._settings["local_repository"]).exists():
            repo = Repo(self._settings["local_repository"])
        else:
            logger.warning(
                f"local working copy of repository '{self._settings['local_repository']}' does not exist, cloning from remote: '{self._settings['remote_repository']}'"
            )
            if self._settings["clone_type"] == "ssh":
                repo = Repo.clone_from(
                    f"ssh://git@github.com/{self._settings['remote_repository']}.git",
                    self._settings["local_repository"],
                    branch=self._settings["branch"],
                    env={"GIT_SSH_COMMAND": f"ssh -i '{str(abs_deploy_key_path)}'"},
                )
            else:
                repo = Repo.clone_from(
                    f"https://oauth2:{self._settings['personal_access_token']}@github.com/{self._settings['remote_repository']}.git",
                    self._settings["local_repository"],
                    branch=self._settings["branch"],
                    env={"GIT_SSH_COMMAND": f"ssh -i '{str(abs_deploy_key_path)}'"},
                )

        repo.git.update_environment(GIT_SSH_COMMAND=f"ssh -i '{str(abs_deploy_key_path)}'")

        logger.info(f"checking out branch '{self._settings['branch']}' and pulling from origin")
        repo.git.checkout(self._settings["branch"])
        repo.remotes.origin.pull()

        logger.info("local working copy of repository is up-to-date and ready")

        return repo

    def update_cve_file(self, cve: dict) -> None:
        dest_file: Path = util.get_cve_json_path(cve["cve"]["id"], path_prefix=self._settings["local_repository"])

        bucket: Path = dest_file.parent
        bucket.mkdir(parents=True, exist_ok=True)

        logger.info(f"writing {dest_file}")
        dest_file.write_text(json.dumps(cve["cve"], indent=2))

    def get_repo_cache_delta_for_cve(self, cve: dict) -> RepoCacheDelta:
        dest_file: Path = util.get_cve_json_path(cve["cve"]["id"], path_prefix=self._settings["local_repository"])
        cache_hash: str = sha256(json.dumps(cve["cve"], indent=2).encode()).hexdigest()
        fs_hash: str = (
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"  # hexdigest of "{}" empty json file
        )
        fs_last_modified: datetime = datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")
        cache_last_modified: datetime = datetime.fromisoformat(cve["cve"]["lastModified"])
        new: bool = not dest_file.exists()

        if not new:
            fs_cve: dict = json.loads(dest_file.read_text())
            fs_hash = sha256(json.dumps(fs_cve, indent=2).encode()).hexdigest()
            fs_last_modified = fs_cve["lastModified"]

        changed: bool = fs_hash != cache_hash

        return RepoCacheDelta(
            id=cve["cve"]["id"],
            cve=cve,
            changed=changed,
            new=new,
            fs_hash=fs_hash,
            cache_hash=cache_hash,
            fs_last_modified=fs_last_modified,
            cache_last_modified=cache_last_modified,
        )

    def get_repo_cache_deltas(self, cves: list[dict]) -> list[RepoCacheDelta]:
        deltas: list[RepoCacheDelta] = [self.get_repo_cache_delta_for_cve(cve) for cve in cves]
        return sorted(deltas, key=operator.attrgetter("id"))

    def update_readme_file(self, updated: list[RepoCacheDelta], new_time_anchor: datetime) -> None:
        logger.debug("generating updated README.md statistics")
        stats: dict[str, Any] = self._generate_readme_stats(updated, new_time_anchor)
        logger.debug(f"updated database statistics: {stats}")
        logger.info(f"writing README.md")
        Path(f"{self._settings['local_repository']}/README.md").write_text(self._render_readme_template(stats))

    def update_state_file(self, deltas: list[RepoCacheDelta]) -> None:
        logger.debug("writing _state.csv updates")

        with Path(f"{self._settings['local_repository']}/_state.csv").open("w") as s:
            writer = csv.DictWriter(s, fieldnames=["cve", "new", "changed", "sha256", "lastModifiedNVD"])
            writer.writeheader()
            for delta in deltas:
                writer.writerow(
                    {
                        "cve": delta.cve["cve"]["id"],
                        "new": int(delta.new),
                        "changed": int(delta.changed),
                        "sha256": delta.cache_hash,
                        "lastModifiedNVD": delta.cache_last_modified.isoformat(),
                    }
                )
        logger.debug(f"updated _state.csv")

    def _render_readme_template(self, stats: dict) -> str:
        template_path: Path = Path(self._settings["readme_template"])
        template_name = template_path.name
        search_path = template_path.parent

        env: jinja2.Environment = jinja2.Environment(
            loader=jinja2.FileSystemLoader(searchpath=str(search_path)), autoescape=True
        )
        template: jinja2.Template = env.get_template(template_name)

        return template.render(**stats)

    def _generate_readme_stats(self, updated: list[RepoCacheDelta], new_time_anchor: datetime) -> dict[str, Any]:
        update_timestamp: datetime = new_time_anchor
        sync_timestamp: datetime = self._time_anchors.sync_nvd
        release_timestamp: datetime = self._time_anchors.release_git_package

        # count all CVEs up to "new_time_anchor"
        cve_total_count: int = self._nos.count_cves_within_date_range(
            "lastModified",
            datetime.fromisoformat("1970-01-01T00:00:00.000+00:00"),
            new_time_anchor,
        )

        added: list[tuple] = []
        modified: list[tuple] = []

        for delta in updated:
            relative_github_url = str(util.get_cve_json_path(delta.cve["cve"]["id"]))
            if delta.new:
                added += [(delta.cve["cve"]["id"], relative_github_url, delta.cve["cve"]["published"])]
            else:
                modified += [(delta.cve["cve"]["id"], relative_github_url, delta.cve["cve"]["lastModified"])]

        return {
            "update_timestamp": update_timestamp.isoformat(),
            "sync_timestamp": sync_timestamp.isoformat(),
            "release_timestamp": release_timestamp.isoformat(),
            "cve_total_count": cve_total_count,
            "cves_added": added,
            "cves_modified": modified,
        }

    def last_auto_update_from_commit_history(self) -> datetime:
        for commit in self.repo.iter_commits(self._settings["branch"]):
            if "Auto-Update: " in str(commit.message):
                return datetime.fromisoformat(str(commit.message).replace("Auto-Update: ", "").strip())

        return datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

    def commit_and_push_auto_update(self, update_timestamp: datetime) -> Commit:
        logger.info(f"committing and pushing auto-update to origin/{self._settings['branch']}")
        self.repo.git.add("--all")
        commit_message: str = f"Auto-Update: {update_timestamp.isoformat()}"
        logger.info(f"commit message: '{commit_message}'")
        commit: Commit = self.repo.index.commit(commit_message)
        self.repo.git.push("origin", self._settings["branch"])

        return commit
