from datetime import datetime, timezone

import service
from loguru import logger
from service.nvd_api import NVDVulnerabilityAPI
from util.config import config
from util.message_card import MessageCard
from util.time_anchor import TimeAnchor


def rebuild_nvd(
    opensearch_client: service.NVDOpenSearch, time_anchors: TimeAnchor, exec_timestamp: datetime
) -> tuple[datetime | None, MessageCard]:

    logger.info("starting data rebuild from NVD API")

    # lock production index
    if opensearch_client.index_is_blocked():
        return time_anchors.rebuild_nvd, MessageCard(
            summary="[Rebuild] Rebuild Opensearch Cache Failed Because Index is Blocked",
            success=False,
            message="[Rebuild] Rebuild Opensearch Cache with fresh NVD data",
            repo=config()["github"]["remote_repository"],
            facts=[],
            action_links=[],
            image="https://nvd.nist.gov/site-media/images/general/A_Brief_History.png",
        )

    nvd_api: NVDVulnerabilityAPI = NVDVulnerabilityAPI()

    try:
        opensearch_client.block_index()
        opensearch_client.snapshot_index()
        opensearch_client.wipe_index()
        total: int = 0
        for chunked_cve_batch, current, total in nvd_api.poll_cve_updates():
            if chunked_cve_batch:
                opensearch_client.bulk_update_cves(chunked_cve_batch)
                total = total
            logger.info(f"rebuild progress: {current}/{total} CVEs")
    except Exception as e:
        logger.warning("catastrophic rebuild failure, restoring from snapshot")
        opensearch_client.wipe_index()
        opensearch_client.restore_snapshot_index()
        logger.warning("restored snapshot")
        raise e
    finally:
        opensearch_client.unblock_index()

    new_time_anchor: datetime = opensearch_client.get_last_mod_cve()[1]

    in_db: int = opensearch_client.count_cves_within_date_range(
        "lastModified", datetime.fromisoformat("1970-01-01T00:00:00.000+00:00"), datetime.now(timezone.utc)
    )

    return new_time_anchor, MessageCard(
        summary="[Rebuild] Rebuild Opensearch Cache with fresh NVD data",
        success=True,
        message="[Rebuild] Rebuild Opensearch Cache with fresh NVD data",
        repo=config()["github"]["remote_repository"],
        facts=[("Timestamp", new_time_anchor.isoformat()), ("Updated", total), ("Total", in_db)],
        action_links=[],
        image="https://nvd.nist.gov/site-media/images/general/A_Brief_History.png",
    )
