from datetime import datetime

import git
import service
from loguru import logger
from service.github_repo import GithubRepo, RepoCacheDelta
from util.config import config
from util.message_card import MessageCard
from util.time_anchor import TimeAnchor


def update_git_repo(
    opensearch_client: service.NVDOpenSearch, time_anchors: TimeAnchor, exec_timestamp: datetime
) -> tuple[datetime, MessageCard]:
    logger.info(f"updating git repository by fetching the latest NVD data from OpenSearch")

    if opensearch_client.index_is_blocked():
        logger.warning(f"skipped auto-update because index is blocked")
        return time_anchors.update_git_repo, MessageCard(
            summary="[Github] Skipped Auto-Update Because Index is Blocked",
            success=False,
            message="[Github] Skipped Auto-Update Because Index is Blocked",
            repo=config()["github"]["remote_repository"],
            facts=[],
            action_links=[],
        )

    repo: GithubRepo = GithubRepo(opensearch_client, time_anchors)
    updated: list[RepoCacheDelta] = []

    modified_since: datetime = repo.last_auto_update_from_commit_history()
    begin_of_time: datetime = datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")

    logger.debug(f"last auto-update commit was at timestamp {modified_since}")

    deltas: list[RepoCacheDelta] = []

    # iterate CVE-year-XXXX, fetch all items, update repo if modified
    for year in range(1999, datetime.utcnow().year + 1):
        cves_per_year: list[dict] = [
            cve
            for cve in opensearch_client.get_cves_by_year_within_mod_range(
                year, start=begin_of_time, stop=exec_timestamp
            )
        ]
        per_year_deltas: list[RepoCacheDelta] = repo.get_repo_cache_deltas(cves_per_year)
        deltas += per_year_deltas
        per_year_changed: list[RepoCacheDelta] = list(filter(lambda d: d.changed, per_year_deltas))
        if per_year_changed:
            logger.info(f"updating {len(per_year_changed)} newly modified CVES from {year}:")
        for delta in per_year_changed:
            repo.update_cve_file(delta.cve)
            updated += [delta]

    if not updated:
        # we didn't change anything, so we won't update the time anchor
        logger.warning(f"there has been no update since the last run of update_git_repo. doing nothing")

        com: git.Commit | git.Tag | git.Tree | git.Blob | None = repo.repo.rev_parse(  # pyright: ignore
            f"origin/{config()['github']['branch']}"
        )
        return time_anchors.update_git_repo, MessageCard(
            summary="[Github] Performed Auto-Update but no files changed",
            success=True,
            message="[Github] Performed Auto-Update but no files changed",
            repo=config()["github"]["remote_repository"],
            facts=[
                ("Timestamp", exec_timestamp.isoformat()),
                ("Author", com.author.name),  # pyright: ignore[reportOptionalMemberAccess]
                ("Message", com.message),  # pyright: ignore[reportOptionalMemberAccess]
                ("Hash", com.hexsha),  # pyright: ignore[reportOptionalMemberAccess]
            ],
            action_links=[
                (
                    "Diff",
                    f"https://github.com/{config()['github']['remote_repository']}/commit/{com.hexsha}",  # pyright: ignore[reportOptionalMemberAccess]
                )
            ],
        )

    # generate stats in readme file an
    repo.update_readme_file(updated, exec_timestamp)
    repo.update_state_file(deltas)
    commit: git.Commit = repo.commit_and_push_auto_update(exec_timestamp)

    return exec_timestamp, MessageCard(
        summary="[Github] Pushed new Auto-Update Commit to Github Repository",
        success=True,
        message="[Github] Pushed new Auto-Update Commit to Github Repository",
        repo=config()["github"]["remote_repository"],
        facts=[
            ("Timestamp", exec_timestamp.isoformat()),
            ("Author", commit.author.name),
            ("Message", commit.message),
            ("Hash", commit.hexsha),
        ],
        action_links=[("Release", f"https://github.com/{config()['github']['remote_repository']}/releases/latest")],
    )
