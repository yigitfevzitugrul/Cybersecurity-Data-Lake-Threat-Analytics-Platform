"""Telegram Bot API yardımcıları (yalnızca standart kütüphane)."""
import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

API = "https://api.telegram.org/bot{token}/{method}"


def _post(token: str, method: str, body: Optional[bytes], content_type: str, attempts: int) -> dict:
    """Bot API çağrısı. Bağlantı ara sıra kopabildiği için birkaç kez dener."""
    request = urllib.request.Request(API.format(token=token, method=method), body, {"Content-Type": content_type})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)["result"]
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Telegram {method} hatası: {exc.code} {exc.read().decode()[:200]}") from None
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if attempt == attempts - 1:
                raise
            time.sleep(3)


def call(token: str, method: str, payload: Optional[dict] = None, attempts: int = 6) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    return _post(token, method, body, "application/json", attempts)


def multipart(fields: dict, file_field: str, path: Path) -> tuple[bytes, str]:
    """Dosya yüklemek için multipart/form-data gövdesi ve içerik türü."""
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
    )
    parts.append(path.read_bytes())
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send_message(token: str, chat_id, text: str) -> dict:
    return call(token, "sendMessage", {"chat_id": chat_id, "text": text})


def send_document(token: str, chat_id, path: Path, caption: str = "", attempts: int = 6) -> dict:
    body, content_type = multipart({"chat_id": chat_id, "caption": caption}, "document", Path(path))
    return _post(token, "sendDocument", body, content_type, attempts)
