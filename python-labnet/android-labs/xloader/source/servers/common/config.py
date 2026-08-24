from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


LAB_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = LAB_ROOT / "config" / "lab.toml"


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open("rb") as handle:
        return tomllib.load(handle)


def lab_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return LAB_ROOT / path


def ensure_runtime_directories(config: dict[str, Any] | None = None) -> None:
    cfg = config or load_config()
    override = os.environ.get("XLOADER_LOG_DIR")
    directory = Path(override) if override else lab_path(cfg["logging"]["directory"])
    directory.mkdir(parents=True, exist_ok=True)


def runtime_log_path(filename: str) -> Path:
    override = os.environ.get("XLOADER_LOG_DIR")
    directory = Path(override) if override else lab_path("logs")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / filename
