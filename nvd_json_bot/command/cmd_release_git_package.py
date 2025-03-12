from datetime import datetime, timedelta

import service
from loguru import logger
from util.config import config
from util.message_card import MessageCard
from util.time_anchor import TimeAnchor


def release_git_package(
    opensearch_client: service.NVDOpenSearch, time_anchors: TimeAnchor, exec_timestamp: datetime
) -> tuple[datetime, MessageCard]:

    if opensearch_client.index_is_blocked():
        logger.warning(f"skipped feed creation because index is blocked")
        return time_anchors.release_git_package, MessageCard(
            summary="[Release] Skipped Feed Creation Because Index is Blocked",
            success=False,
            message="[Release] Skipped Feed Creation Because Index is Blocked",
            repo=config()["github"]["remote_repository"],
            facts=[],
            action_links=[],
        )

    begin_of_time: datetime = datetime.fromisoformat("1970-01-01T00:00:00.000+00:00")
    eight_days_before: datetime = exec_timestamp - timedelta(days=8)

    version: str
    sha: str

    with service.FeedRelease() as release:
        # Step 1: Create and compress all feeds

        # 1.1 CVE-YYYY.json.xz
        for year in range(1999, datetime.utcnow().year + 1):
            cve_per_year: list[dict] = [
                cve["cve"]
                for cve in opensearch_client.get_cves_by_year_within_mod_range(year, begin_of_time, exec_timestamp)
            ]
            release.create_feed_json_xz(f"CVE-{year}", cve_per_year, exec_timestamp)

        # 1.2 CVE-modified.json.xz
        cve_modified: list[dict] = [
            cve["cve"] for cve in opensearch_client.get_cves_by_mod_range(eight_days_before, exec_timestamp)
        ]
        release.create_feed_json_xz("CVE-modified", cve_modified, exec_timestamp)
        del cve_modified

        # 1.3 CVE-recent.json.xz
        cve_recent: list[dict] = [
            cve["cve"] for cve in opensearch_client.get_cves_by_published_range(eight_days_before, exec_timestamp)
        ]
        release.create_feed_json_xz("CVE-recent", cve_recent, exec_timestamp)
        del cve_recent

        # 1.4 CVE-all.json.xz
        cve_all: list[dict] = [
            cve["cve"] for cve in opensearch_client.get_cves_by_published_range(begin_of_time, exec_timestamp)
        ]
        release.create_feed_json_xz("CVE-all", cve_all, exec_timestamp)

        del cve_all

        # Step 2: Upload new Release and remove all old ones to save storage @ github
        version: str
        sha: str
        version, sha = release.publish(exec_timestamp)
        release.prune_old()

    return exec_timestamp, MessageCard(
        summary="[Release] Created New JSON Feed Release",
        success=True,
        message="[Release] Created New JSON Feed Release",
        repo=config()["github"]["remote_repository"],
        facts=[("Timestamp", exec_timestamp.isoformat()), ("Version", version), ("Commit", sha)],
        action_links=[("Release", f"https://github.com/{config()['github']['remote_repository']}/releases/latest")],
    )
