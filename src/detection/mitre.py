"""Alarmların MITRE ATT&CK (Enterprise) eşlemesi.

Her alarm, kuralına ve ayrıntılarına göre bir taktik ve bir ya da birkaç teknikle
etiketlenir. ATT&CK bazı teknikleri birden çok taktiğe bağlar (ör. Valid Accounts);
burada her teknik, bu projedeki bağlamına uyan tek taktikle kayıtlıdır.
"""
from typing import NamedTuple, Optional

from src.detection.rules import (
    AUTH_ANOMALY, BRUTE_FORCE, ESCALATION_CHAIN, PASSWORD_SPRAY, PRIVILEGE_ABUSE,
    SENSITIVE_COMMAND, SUCCESS_AFTER_FAILURES, SUSPICIOUS_IP, Alert,
)
from src.etl.parser import SU_FAILURE, SUDO_AUTH_FAILURE, SUDO_COMMAND, SUDO_NOT_ALLOWED

INITIAL_ACCESS = ("TA0001", "Initial Access")
PERSISTENCE = ("TA0003", "Persistence")
PRIVILEGE_ESCALATION = ("TA0004", "Privilege Escalation")
CREDENTIAL_ACCESS = ("TA0006", "Credential Access")


class Technique(NamedTuple):
    name: str
    tactic: tuple[str, str]  # (kimlik, ad)


TECHNIQUES = {
    "T1110": Technique("Brute Force", CREDENTIAL_ACCESS),
    "T1110.001": Technique("Brute Force: Password Guessing", CREDENTIAL_ACCESS),
    "T1110.003": Technique("Brute Force: Password Spraying", CREDENTIAL_ACCESS),
    "T1078.003": Technique("Valid Accounts: Local Accounts", INITIAL_ACCESS),
    "T1548.001": Technique("Abuse Elevation Control Mechanism: Setuid and Setgid", PRIVILEGE_ESCALATION),
    "T1548.003": Technique("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", PRIVILEGE_ESCALATION),
    "T1003.008": Technique("OS Credential Dumping: /etc/passwd and /etc/shadow", CREDENTIAL_ACCESS),
    "T1136.001": Technique("Create Account: Local Account", PERSISTENCE),
    "T1098": Technique("Account Manipulation", PERSISTENCE),
}

SUDO_TYPES = (SUDO_AUTH_FAILURE, SUDO_NOT_ALLOWED, SUDO_COMMAND)


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def techniques_for(alert: Alert) -> list[str]:
    """Alarmın teknikleri; ilki alarmın taktiğini belirler."""
    details = alert.details
    if alert.rule == BRUTE_FORCE:
        return ["T1110.001"]
    if alert.rule == PASSWORD_SPRAY:
        return ["T1110.003"]
    if alert.rule == SUSPICIOUS_IP:
        # root / olmayan kullanıcılar, birden çok sunucu: hedefi belirsiz parola denemesi.
        return ["T1110"]
    if alert.rule == AUTH_ANOMALY:
        # Geçerli bir hesapla giriş; parola tahminle elde edildiyse Password Guessing de.
        if SUCCESS_AFTER_FAILURES in details.get("reasons", []):
            return ["T1078.003", "T1110.001"]
        return ["T1078.003"]
    if alert.rule == PRIVILEGE_ABUSE:
        failures = details.get("failures_by_type", {})
        result = []
        if any(t in failures for t in SUDO_TYPES):
            result.append("T1548.003")
        if SU_FAILURE in failures:
            result.append("T1110.001")  # su ile hedef hesabın parolasını tahmin etme
        return result
    if alert.rule == SENSITIVE_COMMAND:
        return list(details.get("techniques", []))
    if alert.rule == ESCALATION_CHAIN:
        result = ["T1078.003"]
        if any(t in details.get("privilege_events", {}) for t in SUDO_TYPES):
            result.append("T1548.003")
        if SU_FAILURE in details.get("privilege_events", {}):
            result.append("T1110.001")
        return result
    return []


def tactic_for(alert: Alert, techniques: list[str]) -> Optional[str]:
    """Alarmın taktiği. Saldırı zinciri her zaman yetki yükseltmedir; diğerlerinde ilk teknik belirler."""
    if alert.rule == ESCALATION_CHAIN:
        return PRIVILEGE_ESCALATION[1]
    return TECHNIQUES[techniques[0]].tactic[1] if techniques else None


def classify(alert: Alert) -> tuple[Optional[str], list[str]]:
    techniques = techniques_for(alert)
    unknown = [t for t in techniques if t not in TECHNIQUES]
    if unknown:
        raise ValueError(f"ATT&CK tablosunda olmayan teknik: {unknown}")
    return tactic_for(alert, techniques), techniques


def reference_rows() -> list[tuple]:
    """attack_techniques tablosunun satırları: (teknik, ad, taktik kimliği, taktik, bağlantı)."""
    return [
        (tid, t.name, t.tactic[0], t.tactic[1], technique_url(tid))
        for tid, t in TECHNIQUES.items()
    ]
