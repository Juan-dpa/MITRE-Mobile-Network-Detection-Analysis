from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Endpoint:
    host: str
    ip: str
    port: int


@dataclass(frozen=True)
class LabConfig:
    project_id: str = "drinik-lab-project"
    sender_id: str = "123456789012"
    firebase_app_id: str = "1:123456789012:android:driniklab"
    api_key: str = "AIzaSyDrinikLabKey"
    uid: str = "UID-DRINIK-LAB-001"

    c2: Endpoint = Endpoint("gia.3utilities.com", "198.12.107.13", 80)
    firebase_api: Endpoint = Endpoint("firebaseinstallations.googleapis.com", "172.217.114.4", 443)
    android_api_host: str = "android.apis.google.com"
    fcm_api_host: str = "fcm.googleapis.com"
    mtalk: Endpoint = Endpoint("mtalk.google.com", "108.177.15.188", 5228)
    download: Endpoint = Endpoint("192.3.124.14", "192.3.124.14", 80)
    dns_ip: str = "8.8.8.8"
    dns_port: int = 53

    download_path: str = "/AApk.apk"
    c2_path: str = "/iaserver.php"
    fcm_installations_path: str = "/v1/projects/drinik-lab-project/installations"
    fcm_register_path: str = "/c2dm/register3"
    fcm_send_path: str = "/v1/projects/drinik-lab-project/messages:send"

    user_agent_android: str = (
        "Dalvik/2.1.0 (Linux; U; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.006)"
    )
    user_agent_download_manager: str = (
        "AndroidDownloadManager/12 (Linux; U; Android 12; sdk_gphone64_x86_64 Build/SE1A.220826.006)"
    )

    command_delay_seconds: float = 0.5
    start_delay_seconds: float = 0.5
    timeout_seconds: float = 8.0


@dataclass(frozen=True)
class RuntimePaths:
    root: Path
    cert_dir: Path
    ssl_keylog: Path

    @classmethod
    def under(cls, root: Path) -> "RuntimePaths":
        runtime = root / "runtime"
        return cls(
            root=runtime,
            cert_dir=runtime / "certs",
            ssl_keylog=runtime / "sslkeys.log",
        )
