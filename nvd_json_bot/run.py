import argparse
import traceback
from pathlib import Path

import command
import requests
from loguru import logger
from packaging.version import Version
from util import config

__VERSION__ = Version("0.1.0")

from util.message_card import MessageCard


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", type=Path, default=Path("data/config.json"))
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("sync_nvd", help="sync an opensearch cluster to the online NVD state")
    subparsers.add_parser(
        "update_git_repo", help="Dump NVD data from an OpenSearch Cluster into the json data feeds repo"
    )
    subparsers.add_parser(
        "release_git_package", help="Create a Github release package of NVD data from the OpenSearch Cluster"
    )
    subparsers.add_parser("rebuild_nvd", help="Safely rebuild the NVD data")

    return parser.parse_args()


def setup_logging():
    settings = config.config()["logging"]
    logger.level(settings["level"])
    logger.add(
        settings["log_path"],
        rotation=settings["rotation"],
        level=settings["level"],
        compression=settings["compression"],
    )


def error_message(_: BaseException):
    if not config.config()["teams"]["enabled"]:
        return

    message: MessageCard = MessageCard(
        summary="[ERROR] Execution Failed",
        success=False,
        message=f"[ERROR] Execution Failed\n\n```\n{traceback.format_exc()}\n```",
        repo="-",
        facts=[],
        action_links=[],
        image="",
    )
    requests.post(config.config()["teams"]["connector_url"], json=message.json(), timeout=60)


@logger.catch(onerror=error_message)
def main():
    args: argparse.Namespace = parse_args()
    config.config(args.config)
    setup_logging()

    logger.info(f"nvd_json_bot {__VERSION__}")
    command.execute(args.command)


if __name__ == "__main__":
    main()
