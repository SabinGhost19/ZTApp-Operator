import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import LOG_LEVEL


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        for key in [
            "reconcile_id",
            "zta_name",
            "zta_namespace",
            "zta_uid",
            "phase",
            "resource_kind",
            "resource_name",
            "event",
        ]:
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("zta-operator")
    if logger.handlers:
        return logger

    logger.setLevel(LOG_LEVEL.upper())
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def new_reconcile_id() -> str:
    return str(uuid.uuid4())


def ctx(name: str, namespace: str, uid: str, reconcile_id: str, phase: str | None = None) -> dict[str, Any]:
    base = {
        "zta_name": name,
        "zta_namespace": namespace,
        "zta_uid": uid,
        "reconcile_id": reconcile_id,
    }
    if phase:
        base["phase"] = phase
    return base
