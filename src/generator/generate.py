"""Gömülü saldırılar içeren sentetik OpenSSH auth logu üretir.

Çıktılar:
  - log dosyası     : gerçek sshd satır formatında, zamana göre sıralı
  - etiket dosyası  : gömülen her saldırının kaydı (ground truth); tespit
                      kurallarının doğruluğunu ölçmek için kullanılır

Aynı --seed her zaman aynı çıktıyı üretir. Dış IP'ler dokümantasyon için
ayrılmış bloklardan (RFC 5737) seçilir; gerçek adreslere denk gelmez.
"""
import argparse
import ipaddress
import json
import random
from datetime import date, datetime, time, timedelta
from pathlib import Path

HOST = "srv-auth01"

LEGIT_USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]
COMMON_USERNAMES = [
    "admin", "test", "oracle", "guest", "ubuntu", "postgres", "git", "ftpuser",
    "support", "user", "pi", "nagios", "deploy", "jenkins", "tomcat", "mysql",
    "www", "backup", "operator", "info", "webmaster", "hadoop", "vagrant", "ansible",
    "student", "demo", "service", "monitor", "dev", "staging", "minecraft", "teamspeak",
    "zabbix", "elastic", "redis", "docker", "centos", "debian", "ec2-user", "administrator",
]
EXTERNAL_NETWORKS = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]

BRUTE_FORCE = "brute_force"
PASSWORD_SPRAY = "password_spray"
SUCCESS_AFTER_FAILURES = "success_after_failures"
OFF_HOURS_NEW_IP = "off_hours_new_ip_login"


class LogBuilder:
    """sshd satırlarını biriktirir; her bağlantıya artan bir pid verir."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.entries: list[tuple[datetime, int, str]] = []
        self._pid = rng.randint(2000, 9000)

    def _add(self, ts: datetime, pid: int, message: str) -> None:
        line = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} sshd[{pid}]: {message}"
        self.entries.append((ts, len(self.entries), line))

    def _new_connection(self) -> tuple[int, int]:
        self._pid += self.rng.randint(1, 7)
        return self._pid, self.rng.randint(1024, 65535)

    def failed(self, ts: datetime, user: str, ip: str) -> None:
        pid, port = self._new_connection()
        if user in LEGIT_USERS or user == "root":
            self._add(ts, pid, f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            self._add(ts, pid, f"Invalid user {user} from {ip}")
            self._add(ts, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        self._add(ts, pid, f"Connection closed by {ip} [preauth]")

    def accepted(self, ts: datetime, user: str, ip: str) -> None:
        pid, port = self._new_connection()
        self._add(ts, pid, f"Accepted password for {user} from {ip} port {port} ssh2")
        self._add(ts, pid, f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")

    def lines(self) -> list[str]:
        return [line for _, _, line in sorted(self.entries)]


def _label(attack_type, ip, users, times, failed, succeeded) -> dict:
    return {
        "attack_type": attack_type,
        "source_ip": ip,
        "target_users": sorted(set(users)),
        "start_time": min(times).isoformat(),
        "end_time": max(times).isoformat(),
        "failed_attempts": failed,
        "succeeded": succeeded,
    }


def _brute_force(log, rng, day_start, ip, then_succeed: bool) -> dict:
    """Tek IP → tek kullanıcı, birkaç saniye arayla çok sayıda deneme."""
    user = rng.choice(LEGIT_USERS) if then_succeed else rng.choice(["root"] + LEGIT_USERS)
    attempts = rng.randint(15, 40) if then_succeed else rng.randint(40, 120)
    ts = day_start + timedelta(seconds=rng.randint(0, 22 * 3600))
    times = []
    for _ in range(attempts):
        log.failed(ts, user, ip)
        times.append(ts)
        ts += timedelta(seconds=rng.randint(2, 4))
    if then_succeed:
        log.accepted(ts, user, ip)
        times.append(ts)
    attack_type = SUCCESS_AFTER_FAILURES if then_succeed else BRUTE_FORCE
    return _label(attack_type, ip, [user], times, attempts, then_succeed)


def _password_spray(log, rng, day_start, ip) -> dict:
    """Tek IP → çok farklı kullanıcı, her birine tek deneme."""
    users = rng.sample(LEGIT_USERS + COMMON_USERNAMES, rng.randint(25, 40))
    ts = day_start + timedelta(seconds=rng.randint(0, 22 * 3600))
    times = []
    for user in users:
        log.failed(ts, user, ip)
        times.append(ts)
        ts += timedelta(seconds=rng.randint(5, 20))
    return _label(PASSWORD_SPRAY, ip, users, times, len(users), False)


def _off_hours_login(log, rng, day_start, ip) -> dict:
    """Geçerli kullanıcı, gece saatinde, daha önce hiç kullanmadığı bir IP'den giriş yapar."""
    user = rng.choice(LEGIT_USERS)
    ts = day_start + timedelta(seconds=rng.randint(2 * 3600, 5 * 3600 - 1))
    log.accepted(ts, user, ip)
    return _label(OFF_HOURS_NEW_IP, ip, [user], [ts], 0, True)


def _normal_traffic(log, rng, day_start, home_ips) -> None:
    """Mesai saatlerinde kendi IP'sinden giren kullanıcılar; ara sıra şifre yazım hatası."""
    for user in LEGIT_USERS:
        for _ in range(rng.randint(2, 4)):
            ts = day_start + timedelta(seconds=rng.randint(8 * 3600, 18 * 3600 - 60))
            if rng.random() < 0.10:
                for _ in range(rng.randint(1, 2)):
                    log.failed(ts, user, home_ips[user])
                    ts += timedelta(seconds=rng.randint(4, 10))
            log.accepted(ts, user, home_ips[user])


def _background_noise(log, rng, day_start, noise_pool, ips_per_day) -> None:
    """İnternet gürültüsü: rastgele IP'lerden birkaç dağınık başarısız deneme."""
    for _ in range(ips_per_day):
        ip = rng.choice(noise_pool)
        ts = day_start + timedelta(seconds=rng.randint(0, 86400 - 600))
        for _ in range(rng.randint(1, 3)):
            log.failed(ts, rng.choice(["root"] + COMMON_USERNAMES), ip)
            ts += timedelta(seconds=rng.randint(3, 120))


def generate(start_date: date, days: int = 1, seed: int = 42, noise_ips_per_day: int = 30):
    """(log satırları, etiket sözlüğü) döndürür. Her güne 4 saldırı tipinden birer tane gömülür."""
    rng = random.Random(seed)
    log = LogBuilder(rng)

    external = [str(ip) for net in EXTERNAL_NETWORKS for ip in ipaddress.ip_network(net).hosts()]
    rng.shuffle(external)
    attacks_per_day = 4
    needed = days * attacks_per_day
    if needed >= len(external):
        raise ValueError(f"en fazla {len(external) // attacks_per_day - 1} gün üretilebilir")
    # Saldırgan IP'leri gürültü havuzundan ayrı tutulur ki etiketler net kalsın.
    attacker_ips, noise_pool = external[:needed], external[needed:]
    home_ips = {user: f"10.20.0.{10 + i}" for i, user in enumerate(LEGIT_USERS)}

    attacks = []
    for d in range(days):
        day_start = datetime.combine(start_date + timedelta(days=d), time.min)
        _normal_traffic(log, rng, day_start, home_ips)
        _background_noise(log, rng, day_start, noise_pool, noise_ips_per_day)
        ips = attacker_ips[d * attacks_per_day:(d + 1) * attacks_per_day]
        attacks.append(_brute_force(log, rng, day_start, ips[0], then_succeed=False))
        attacks.append(_password_spray(log, rng, day_start, ips[1]))
        attacks.append(_brute_force(log, rng, day_start, ips[2], then_succeed=True))
        attacks.append(_off_hours_login(log, rng, day_start, ips[3]))

    attacks.sort(key=lambda a: a["start_time"])
    for i, attack in enumerate(attacks, start=1):
        attack["attack_id"] = i
    labels = {
        "seed": seed,
        "start_date": start_date.isoformat(),
        "days": days,
        "host": HOST,
        "legit_users": home_ips,
        "attacks": attacks,
    }
    return log.lines(), labels


def main() -> None:
    ap = argparse.ArgumentParser(description="Gömülü saldırılarla sentetik auth logu üretir.")
    ap.add_argument("--start-date", type=date.fromisoformat, required=True, help="YYYY-MM-DD")
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/raw/synthetic_auth.log")
    args = ap.parse_args()

    lines, labels = generate(args.start_date, args.days, args.seed)
    out = Path(args.out)
    labels_path = out.with_name(out.stem + "_labels.json")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    labels_path.write_text(json.dumps(labels, indent=2), encoding="utf-8")

    print(f"Log     : {out} ({len(lines)} satır)")
    print(f"Etiket  : {labels_path} ({len(labels['attacks'])} saldırı)")
    for a in labels["attacks"]:
        print(f"  #{a['attack_id']} {a['attack_type']:<24} {a['source_ip']:<16} "
              f"{a['failed_attempts']:>3} başarısız, başarı={a['succeeded']}  {a['start_time']}")


if __name__ == "__main__":
    main()
