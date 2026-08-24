from __future__ import annotations

import datetime as dt
import threading


_LOCK = threading.Lock()


def log(component: str, message: str) -> None:
    now = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    with _LOCK:
        print(f"[{now}] [{component:<10}] {message}", flush=True)

