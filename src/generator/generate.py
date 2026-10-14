"""Gömülü saldırılar içeren sentetik Linux auth logu (sshd, sudo, su) üretir.

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
from collections import Counter
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
SLOW_BRUTE_FORCE = "slow_brute_force"
PRIVILEGE_ESCALATION = "privilege_escalation"
SU_BRUTEFORCE = "su_bruteforce"

# sudo yetkisi olan kullanıcılar; diğerleri sudoers dosyasında değildir.
ADMINS = ["alice", "bob", "carol"]
ROUTINE_SUDO_COMMANDS = [
    "/usr/bin/apt update",
    "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status postgresql",
    "/usr/bin/journalctl -u ssh --since today",
    "/usr/bin/tail -n 100 /var/log/syslog",
    "/usr/bin/docker ps",
]
# Ele geçirilmiş bir yönetici hesabıyla yapılan tipik adımlar: yetkileri listele,
# parola özetlerini oku, root yetkili gizli bir kullanıcı ekle.
ATTACKER_SUDO_COMMANDS = ["list", "/bin/cat /etc/shadow", "/usr/sbin/useradd -o -u 0 -g 0 -M sysupdate"]


class LogBuilder:
    """sshd satırlarını biriktirir; her bağlantıya artan bir pid verir."""

    def __init__(self, rng: random.Random):
        self.rng = rng
        self.entries: list[tuple[datetime, int, str]] = []
        self._pid = rng.randint(2000, 9000)

    def _add_line(self, ts: datetime, process: str, message: str) -> None:
        line = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {process}: {message}"
        self.entries.append((ts, len(self.entries), line))

    def _add(self, ts: datetime, pid: int, message: str) -> None:
        self._add_line(ts, f"sshd[{pid}]", message)

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

    def sudo(self, ts: datetime, user: str, command: str, tty: str, status: str = "") -> None:
        """status boşsa izin verilmiş komut; aksi halde sudo'nun hata mesajı."""
        prefix = f"{status} ; " if status else ""
        self._add_line(
            ts, "sudo", f"   {user} : {prefix}TTY={tty} ; PWD=/home/{user} ; USER=root ; COMMAND={command}"
        )

    def su(self, ts: datetime, user: str, tty: str, ok: bool) -> None:
        self._pid += self.rng.randint(1, 7)
        if ok:
            self._add_line(ts, f"su[{self._pid}]", f"(to root) {user} on {tty}")
            # Aynı girişimin pam kaydı; ayrıştırıcı bunu tekrar saymaz.
            self._add_line(ts, f"su[{self._pid}]", f"pam_unix(su:session): session opened for user root by {user}(uid=1000)")
        else:
            self._add_line(ts, f"su[{self._pid}]", f"FAILED SU (to root) {user} on {tty}")



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


BAD_LINE_KINDS = [
    "malformed_line", "invalid_timestamp", "invalid_ip", "invalid_port", "missing_field", "duplicate",
]


def _inject_bad_lines(lines: list[str], rng: random.Random, ratio: float) -> tuple[list[str], dict]:
    """Veri kalitesi kontrollerini sınamak için bozuk satırlar ekler.

    Her tür, pipeline'da aynı isimli red sebebiyle karantinaya düşmelidir.
    (yeni satır listesi, {tür: adet}) döndürür.
    """
    count = round(len(lines) * ratio)
    auth_indexes = [i for i, line in enumerate(lines) if " password for " in line]
    injections = []
    counts: Counter = Counter()
    for n in range(count):
        kind = BAD_LINE_KINDS[n % len(BAD_LINE_KINDS)]
        i = rng.choice(auth_indexes) if kind == "duplicate" else rng.randrange(len(lines))
        # Zaman sırası bozulmasın diye komşu satırın zaman damgası kullanılır.
        stamp = lines[i][:15]
        prefix = f"{stamp} {HOST} sshd[{rng.randint(2000, 60000)}]: "
        port = rng.randint(1024, 65535)
        if kind == "malformed_line":
            bad = rng.choice(["#### corrupted log entry ####", prefix + "Failed password for root from"])
        elif kind == "invalid_timestamp":
            bad = f"Feb 30 {stamp[7:]} {HOST} sshd[{port}]: Failed password for root from 192.0.2.1 port {port} ssh2"
        elif kind == "invalid_ip":
            bad = prefix + f"Failed password for root from 999.{rng.randint(0, 255)}.{rng.randint(0, 255)}.1 port {port} ssh2"
        elif kind == "invalid_port":
            bad = prefix + f"Failed password for root from 192.0.2.1 port {rng.randint(65536, 99999)} ssh2"
        elif kind == "missing_field":
            bad = prefix + f"Failed password for  from 192.0.2.1 port {port} ssh2"
        else:
            bad = lines[i]
        injections.append((i, bad))
        counts[kind] += 1

    result = list(lines)
    for i, bad in sorted(injections, key=lambda item: item[0], reverse=True):
        result.insert(i + 1, bad)
    return result, dict(counts)


def _hard_cases(rng: random.Random, start_date: date, days: int, home_ips: dict):
    """Tespit kurallarını zorlayan durumlar; (satır kayıtları, saldırılar, zararsız benzerler) döndürür.

    Her güne iki durum eklenir:
      - slow_brute_force  : eşiklerin altında kalacak kadar yavaş bir brute force (kaçırılması beklenir)
      - forgotten_password: şifresini unutan gerçek kullanıcı; kendi IP'sinden art arda
                            başarısız denemeler ve ardından başarılı giriş (yanlış alarm üretmesi beklenir)
    """
    log = LogBuilder(rng)
    attacks, benign = [], []
    for d in range(days):
        day_start = datetime.combine(start_date + timedelta(days=d), time.min)

        # 100.64.0.0/10 (RFC 6598) de internette yönlendirilmeyen bir bloktur.
        ip = f"100.64.{d % 256}.{rng.randint(1, 254)}"
        user = rng.choice(["root"] + LEGIT_USERS)
        ts = day_start + timedelta(seconds=rng.randint(0, 16 * 3600))
        times = []
        for _ in range(rng.randint(20, 30)):
            log.failed(ts, user, ip)
            times.append(ts)
            ts += timedelta(seconds=rng.randint(360, 600))
        attacks.append(_label(SLOW_BRUTE_FORCE, ip, [user], times, len(times), False))

        user = rng.choice(LEGIT_USERS)
        ts = day_start + timedelta(seconds=rng.randint(8 * 3600, 17 * 3600))
        times = []
        for _ in range(rng.randint(10, 14)):
            log.failed(ts, user, home_ips[user])
            times.append(ts)
            ts += timedelta(seconds=rng.randint(3, 8))
        log.accepted(ts, user, home_ips[user])
        benign.append({
            "case": "forgotten_password",
            "username": user,
            "source_ip": home_ips[user],
            "start_time": times[0].isoformat(),
            "end_time": ts.isoformat(),
            "failed_attempts": len(times),
        })
    return log.entries, attacks, benign


def _privilege_label(attack_type, user, ip, times, failed, succeeded) -> dict:
    label = _label(attack_type, ip, [user], times, failed, succeeded)
    label["username"] = user  # sudo / su kayıtlarında IP yoktur; olay kullanıcıyla eşleştirilir.
    return label


def _privilege_activity(rng: random.Random, start_date: date, days: int, base_attacks: list, hard_cases: bool):
    """sudo / su kayıtları üretir; (satır kayıtları, saldırılar, zararsız benzerler) döndürür.

    Her gün:
      - yöneticilerin mesai içindeki olağan sudo komutları (ara sıra bir yanlış parola),
      - privilege_escalation: o günün "başarısızlıklar sonrası başarılı giriş" saldırısında
        ele geçirilen hesapla, girişten birkaç dakika sonra yetki yükseltme denemesi,
      - su_bruteforce: yetkisi olmayan bir kullanıcının art arda root parolası denemesi.
    hard_cases açıksa iki zararsız benzer de eklenir: sudo yetkisi olmayan yeni bir
    çalışanın tek bir sudo denemesi ve bir yöneticinin akşam saatinde açtığı root kabuğu.
    """
    log = LogBuilder(rng)
    tty = lambda: f"pts/{rng.randint(0, 9)}"
    attacks, benign = [], []
    breaches = {a["start_time"][:10]: a for a in base_attacks if a["attack_type"] == SUCCESS_AFTER_FAILURES}
    for d in range(days):
        day = start_date + timedelta(days=d)
        day_start = datetime.combine(day, time.min)

        for admin in ADMINS:
            for _ in range(rng.randint(1, 3)):
                ts = day_start + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
                terminal = tty()
                if rng.random() < 0.10:
                    log.sudo(ts - timedelta(seconds=rng.randint(4, 10)), admin, "/usr/bin/apt update", terminal,
                             "1 incorrect password attempt")
                log.sudo(ts, admin, rng.choice(ROUTINE_SUDO_COMMANDS), terminal)
            if rng.random() < 0.20:
                log.su(day_start + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600)), admin, tty(), ok=True)

        breach = breaches.get(day.isoformat())
        if breach:
            user, ip = breach["target_users"][0], breach["source_ip"]
            ts = datetime.fromisoformat(breach["end_time"]) + timedelta(seconds=rng.randint(60, 300))
            terminal, times, failed = tty(), [], 0
            if user in ADMINS:
                for command in ATTACKER_SUDO_COMMANDS:
                    log.sudo(ts, user, command, terminal)
                    times.append(ts)
                    ts += timedelta(seconds=rng.randint(10, 40))
            else:
                for command in ("list", "/bin/bash"):
                    log.sudo(ts, user, command, terminal, "user NOT in sudoers")
                    times.append(ts)
                    failed += 1
                    ts += timedelta(seconds=rng.randint(10, 40))
                for _ in range(rng.randint(3, 5)):
                    log.su(ts, user, terminal, ok=False)
                    times.append(ts)
                    failed += 1
                    ts += timedelta(seconds=rng.randint(10, 30))
            attacks.append(_privilege_label(PRIVILEGE_ESCALATION, user, ip, times, failed, user in ADMINS))

        insider = rng.choice([u for u in LEGIT_USERS if u not in ADMINS])
        ts = day_start + timedelta(seconds=rng.randint(0, 22 * 3600))
        terminal, times = tty(), []
        for _ in range(rng.randint(6, 10)):
            log.su(ts, insider, terminal, ok=False)
            times.append(ts)
            ts += timedelta(seconds=rng.randint(5, 20))
        attacks.append(_privilege_label(SU_BRUTEFORCE, insider, None, times, len(times), False))

        if hard_cases:
            newcomer = rng.choice([u for u in LEGIT_USERS if u not in ADMINS])
            ts = day_start + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
            log.sudo(ts, newcomer, "/usr/bin/apt update", tty(), "user NOT in sudoers")
            benign.append({"case": "sudo_mistake", "username": newcomer, "source_ip": None,
                           "start_time": ts.isoformat(), "end_time": ts.isoformat(), "failed_attempts": 1})
            admin = rng.choice(ADMINS)
            ts = day_start + timedelta(seconds=rng.randint(20 * 3600, 22 * 3600))
            log.sudo(ts, admin, "/bin/bash", tty())
            benign.append({"case": "admin_root_shell", "username": admin, "source_ip": None,
                           "start_time": ts.isoformat(), "end_time": ts.isoformat(), "failed_attempts": 0})
    return log.entries, attacks, benign


def generate(
    start_date: date,
    days: int = 1,
    seed: int = 42,
    noise_ips_per_day: int = 30,
    bad_ratio: float = 0.0,
    hard_cases: bool = False,
    privilege: bool = False,
):
    """(log satırları, etiket sözlüğü) döndürür. Her güne 4 saldırı tipinden birer tane gömülür.

    bad_ratio > 0 ise temiz satır sayısının o oranı kadar bozuk satır eklenir.
    hard_cases açıksa her güne yavaş bir brute force ve zararsız bir "şifresini
    unutan kullanıcı" durumu eklenir. privilege açıksa sudo / su kayıtları ve iki
    yetki yükseltme saldırısı eklenir (_privilege_activity). Hepsi ayrı RNG kullanır;
    temel satırlar ve temel saldırı etiketleri bu seçeneklerden etkilenmez.
    """
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

    entries = log.entries
    benign = []
    if hard_cases:
        extra_entries, extra_attacks, benign = _hard_cases(random.Random(seed + 2), start_date, days, home_ips)
        offset = len(entries)
        entries = entries + [(ts, offset + seq, line) for ts, seq, line in extra_entries]
        attacks.extend(extra_attacks)
    if privilege:
        extra_entries, extra_attacks, extra_benign = _privilege_activity(
            random.Random(seed + 3), start_date, days, list(attacks), hard_cases
        )
        offset = len(entries)
        entries = entries + [(ts, offset + seq, line) for ts, seq, line in extra_entries]
        attacks.extend(extra_attacks)
        benign = benign + extra_benign
    clean_lines = [line for _, _, line in sorted(entries)]

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
        "benign_lookalikes": benign,
    }
    # Ayrı bir RNG: bozuk satır eklemek temiz çıktıyı değiştirmez.
    lines, labels["injected_bad_lines"] = _inject_bad_lines(clean_lines, random.Random(seed + 1), bad_ratio)
    return lines, labels


def write_files(out: Path, lines: list[str], labels: dict) -> Path:
    """Logu `out` dosyasına, etiketleri yanına `<ad>_labels.json` olarak yazar; etiket yolunu döndürür."""
    out.parent.mkdir(parents=True, exist_ok=True)
    labels_path = out.with_name(out.stem + "_labels.json")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    labels_path.write_text(json.dumps(labels, indent=2), encoding="utf-8")
    return labels_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Gömülü saldırılarla sentetik auth logu üretir.")
    ap.add_argument("--start-date", type=date.fromisoformat, required=True, help="YYYY-MM-DD")
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/raw/synthetic_auth.log")
    ap.add_argument("--bad-ratio", type=float, default=0.0, help="Eklenecek bozuk satır oranı (örn. 0.02)")
    ap.add_argument("--hard-cases", action="store_true",
                    help="Yavaş brute force ve şifresini unutan kullanıcı durumlarını ekle")
    ap.add_argument("--privilege", action="store_true",
                    help="sudo / su kayıtları ve yetki yükseltme saldırıları ekle")
    args = ap.parse_args()

    lines, labels = generate(
        args.start_date, args.days, args.seed, bad_ratio=args.bad_ratio, hard_cases=args.hard_cases,
        privilege=args.privilege,
    )
    out = Path(args.out)
    labels_path = write_files(out, lines, labels)

    print(f"Log     : {out} ({len(lines)} satır)")
    print(f"Etiket  : {labels_path} ({len(labels['attacks'])} saldırı)")
    for a in labels["attacks"]:
        print(f"  #{a['attack_id']} {a['attack_type']:<24} {a['source_ip'] or '-':<16} "
              f"{a['failed_attempts']:>3} başarısız, başarı={a['succeeded']}  {a['start_time']}")
    for b in labels["benign_lookalikes"]:
        print(f"  (zararsız) {b['case']:<21} {b.get('username') or b['source_ip']:<16} "
              f"{b['failed_attempts']:>3} başarısız  {b['start_time']}")
    if labels["injected_bad_lines"]:
        print(f"Bozuk   : {sum(labels['injected_bad_lines'].values())} satır {labels['injected_bad_lines']}")


if __name__ == "__main__":
    main()
