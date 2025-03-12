from datetime import datetime, timezone

import service
from loguru import logger
from service.nvd_api import NVDVulnerabilityAPI
from util.config import config
from util.message_card import MessageCard
from util.time_anchor import TimeAnchor


def sync_nvd(
    opensearch_client: service.NVDOpenSearch, time_anchors: TimeAnchor, _exec_timestamp: datetime
) -> tuple[datetime | None, MessageCard]:

    logger.info("starting synchronization with NVD API and NVD OpenSearch instance")

    nvd_api: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    if opensearch_client.index_is_blocked():
        logger.warning(f"skipped synchronization because index is blocked")
        return time_anchors.sync_nvd, MessageCard(
            summary="[Synchronization] Skipped Synchronization Because Opensearch Index is Blocked",
            success=False,
            message="[Synchronization] Skipped Synchronization Because Opensearch Index is Blocked",
            repo=config()["github"]["remote_repository"],
            action_links=[],
            facts=[],
            image="https://nvd.nist.gov/site-media/images/general/A_Brief_History.png",
        )

    start_timestamp: datetime | None = opensearch_client.get_last_mod_cve()[1]

    total: int = 0

    for chunked_cve_batch, current, total in nvd_api.poll_cve_updates(since=start_timestamp):
        if chunked_cve_batch:
            opensearch_client.bulk_update_cves(chunked_cve_batch)
            total = total
        logger.info(f"synchronization progress: {current}/{total} CVEs")

    new_time_anchor: datetime = opensearch_client.get_last_mod_cve()[1]

    in_db: int = opensearch_client.count_cves_within_date_range(
        "lastModified", datetime.fromisoformat("1970-01-01T00:00:00.000+00:00"), datetime.now(timezone.utc)
    )

    return new_time_anchor, MessageCard(
        summary="[Synchronization] Synchronized Opensearch with NVD",
        success=True,
        message="[Synchronization] Synchronized Opensearch with NVD",
        repo=config()["github"]["remote_repository"],
        facts=[("Timestamp", new_time_anchor.isoformat()), ("Updated", total), ("Total", in_db)],
        action_links=[],
        image="https://nvd.nist.gov/site-media/images/general/A_Brief_History.png",
    )
