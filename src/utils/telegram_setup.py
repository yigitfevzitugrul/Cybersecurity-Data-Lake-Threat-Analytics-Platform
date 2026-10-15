"""Telegram bildirimi kurulumu: chat id'yi bulur, Grafana bildirim kanalı dosyasını yazar.

Grafana, provisioning dosyalarına ortam değişkeninden gelen sayısal değerleri sayıya
çevirir; Telegram kanalı ise chat id'yi metin olarak ister. Bu yüzden chat id dosyaya
doğrudan yazılır. Dosya yereldir (git'e girmez); bot token'ı yine .env'den, ortam
değişkeniyle gelir ve dosyada bulunmaz. Chat id ayrıca .env'ye TELEGRAM_CHAT_ID olarak
yazılır; haftalık raporu gönderen Airflow görevi onu oradan okur.

Önce @BotFather'dan bot oluşturup TELEGRAM_BOT_TOKEN'ı .env'ye ekleyin ve bota bir mesaj
yazın. Sonra:
    python -m src.utils.telegram_setup [--test]
"""
import argparse
from pathlib import Path

from dotenv import dotenv_values

from src.utils.telegram import call, send_message

ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env"
CONTACT_POINT_PATH = ROOT / "grafana" / "alerting" / "telegram_contact_point.local.yaml"

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


def find_chat_id(token: str) -> int:
    """Bota en son yazan özel sohbetin kimliği."""
    chats = [u["message"]["chat"] for u in call(token, "getUpdates") if "message" in u]
    private = [c for c in chats if c["type"] == "private"]
    if not private:
        raise SystemExit("Bota henüz mesaj yazılmamış: Telegram'da botu açıp bir mesaj gönderin.")
    return private[-1]["id"]


def render_contact_point(chat_id: int) -> str:
    return CONTACT_POINT.format(chat_id=chat_id)


def set_env_value(path: Path, key: str, value: str) -> None:
    """`.env` içinde bir anahtarı günceller ya da sona ekler; diğer satırlara dokunmaz."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(f"{key}="):
            lines[i], replaced = f"{key}={value}", True
    if not replaced:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Telegram bildirim kanalını Grafana için hazırlar.")
    ap.add_argument("--test", action="store_true", help="Kurulumdan sonra bir deneme mesajı gönder")
    args = ap.parse_args()

    env = dotenv_values(ENV_PATH)
    token = env.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN .env dosyasında tanımlı değil.")
    bot = call(token, "getMe")["username"]
    # Telegram eski mesajları bir süre sonra getUpdates'ten düşürür; bulunmuş kimlik korunur.
    chat_id = int(env["TELEGRAM_CHAT_ID"]) if env.get("TELEGRAM_CHAT_ID") else find_chat_id(token)
    CONTACT_POINT_PATH.write_text(render_contact_point(chat_id), encoding="utf-8")
    set_env_value(ENV_PATH, "TELEGRAM_CHAT_ID", str(chat_id))
    print(f"Bot      : @{bot}")
    print(f"Sohbet   : {chat_id}")
    print(f"Yazıldı  : {CONTACT_POINT_PATH.relative_to(ROOT)}, .env (TELEGRAM_CHAT_ID)")
    if args.test:
        send_message(token, chat_id, "SecDL: Telegram bildirimi kuruldu.")
        print("Deneme mesajı gönderildi.")
    print("Grafana'yı bildirimlerle başlatmak için:")
    print("  docker compose -f docker-compose.yml -f docker-compose.alerting.yml up -d --wait")


if __name__ == "__main__":
    main()
