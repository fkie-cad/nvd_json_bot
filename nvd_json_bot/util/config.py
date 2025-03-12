import json
from pathlib import Path

from loguru import logger


class _Config:
    config: dict | None = None



def config(config_json_path: str | Path = "") -> dict:
    if config_json_path:
        logger.info(f"reading config file from '{str(config_json_path)}'")
        _Config.config = json.loads(Path(config_json_path).read_text())

    if _Config.config is not None:
        return _Config.config

    raise ValueError("config() must be called with 'config_json_path' parameter at least once")
