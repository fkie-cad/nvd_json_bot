from datetime import datetime, timezone
from typing import Callable

import requests
from loguru import logger
from service import opensearch
from util import config, time_anchor
from util.message_card import MessageCard

from .cmd_rebuild_nvd import rebuild_nvd
from .cmd_release_git_package import release_git_package
from .cmd_sync_nvd import sync_nvd
from .cmd_update_git_repo import update_git_repo

__commands__: dict[str, Callable] = {
    "sync_nvd": sync_nvd,
    "update_git_repo": update_git_repo,
    "release_git_package": release_git_package,
    "rebuild_nvd": rebuild_nvd,
}


def execute(command: str) -> None:
    logger.debug(f"command execution request: '{command}'")

    anchor_path: str = config.config()["time_anchors"]["path"]

    time_anchors: time_anchor.TimeAnchor = time_anchor.TimeAnchor(anchor_path)
    exec_timestamp: datetime = datetime.now(timezone.utc)

    with opensearch.NVDOpenSearch() as nvd_opensearch:
        new_anchor: datetime
        message: MessageCard
        new_anchor, message = __commands__[command](nvd_opensearch, time_anchors, exec_timestamp)
        time_anchors.set_anchor(command, new_anchor)
        if config.config()["teams"]["enabled"]:
            requests.post(config.config()["teams"]["connector_url"], json=message.json())
