"""Telegram bildirimi kurulumu: chat id'yi bulur ve Grafana bildirim kanalı dosyasını yazar.

Grafana, provisioning dosyalarına ortam değişkeninden gelen sayısal değerleri sayıya
çevirir; Telegram kanalı ise chat id'yi metin olarak ister. Bu yüzden chat id dosyaya
doğrudan yazılır. Dosya yereldir (git'e girmez); bot token'ı yine .env'den, ortam
değişkeniyle gelir ve dosyada bulunmaz.

Önce @BotFather'dan bot oluşturup TELEGRAM_BOT_TOKEN'ı .env'ye ekleyin ve bota bir mesaj
yazın. Sonra:
    python -m src.utils.telegram_setup [--test]
"""
import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
CONTACT_POINT_PATH = ROOT / "grafana" / "alerting" / "telegram_contact_point.local.yaml"
API = "https://api.telegram.org/bot{token}/{method}"

CONTACT_POINT = """\
# python -m src.utils.telegram_setup tarafından üretildi; git'e girmez.
apiVersion: 1
contactPoints:
  - orgId: 1
    name: Telegram
    receivers:
      - uid: secdl-telegram
        type: telegram
        disableResolveMessage: true
        settings:
          bottoken: $TELEGRAM_BOT_TOKEN
          chatid: "{chat_id}"
          message: '{{{{ template "secdl.message" . }}}}'
"""


def call(token: str, method: str, payload: Optional[dict] = None, attempts: int = 6) -> dict:
    """Bot API çağrısı. Bağlantı ara sıra kopabildiği için birkaç kez dener."""
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(API.format(token=token, method=method), data, {"Content-Type": "application/json"})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)["result"]
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"Telegram {method} hatası: {exc.code} {exc.read().decode()[:200]}") from None
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if attempt == attempts - 1:
                raise
            time.sleep(3)


def find_chat_id(token: str) -> int:
    """Bota en son yazan özel sohbetin kimliği."""
    chats = [u["message"]["chat"] for u in call(token, "getUpdates") if "message" in u]
    private = [c for c in chats if c["type"] == "private"]
    if not private:
        raise SystemExit("Bota henüz mesaj yazılmamış: Telegram'da botu açıp bir mesaj gönderin.")
    return private[-1]["id"]


def render_contact_point(chat_id: int) -> str:
    return CONTACT_POINT.format(chat_id=chat_id)


def main() -> None:
    ap = argparse.ArgumentParser(description="Telegram bildirim kanalını Grafana için hazırlar.")
    ap.add_argument("--test", action="store_true", help="Kurulumdan sonra bir deneme mesajı gönder")
    args = ap.parse_args()

    token = dotenv_values(ROOT / ".env").get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN .env dosyasında tanımlı değil.")
    bot = call(token, "getMe")["username"]
    chat_id = find_chat_id(token)
    CONTACT_POINT_PATH.write_text(render_contact_point(chat_id), encoding="utf-8")
    print(f"Bot      : @{bot}")
    print(f"Sohbet   : {chat_id}")
    print(f"Yazıldı  : {CONTACT_POINT_PATH.relative_to(ROOT)}")
    if args.test:
        call(token, "sendMessage", {"chat_id": chat_id, "text": "SecDL: Telegram bildirimi kuruldu."})
        print("Deneme mesajı gönderildi.")
    print("Grafana'yı bildirimlerle başlatmak için:")
    print("  docker compose -f docker-compose.yml -f docker-compose.alerting.yml up -d --wait")


if __name__ == "__main__":
    main()
