"""Extract: ham log dosyasını okur."""
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator, Union

SYSLOG_DATE_RE = re.compile(r"^(?P<month>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) ")


@dataclass(frozen=True)
class RawLine:
    line_no: int
    text: str


def file_sha256(path: Union[str, Path]) -> str:
    """Dosya içeriğinin parmak izi; aynı dosyanın tekrar işlendiğini anlamak için kullanılır."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def infer_year(path: Union[str, Path]) -> int:
    """Syslog satırında yıl olmadığı için yılı dosyanın değişiklik zamanından tahmin eder.

    İlk tarihli satır, dosyanın değişiklik zamanından ileride kalıyorsa log bir
    önceki yıla aittir (örn. Ocak'ta kapanan dosyadaki Aralık satırları).
    Bir yıldan eski ya da yıl sınırını aşan dosyalarda yıl elle verilmelidir.
    """
    modified = datetime.fromtimestamp(Path(path).stat().st_mtime)
    for raw in read_lines(path):
        match = SYSLOG_DATE_RE.match(raw.text)
        if match is None:
            continue
        try:
            first = datetime.strptime(f"{modified.year} {match['month']} {match['day']}", "%Y %b %d")
        except ValueError:
            continue
        return modified.year - 1 if first > modified + timedelta(days=1) else modified.year
    return modified.year


def read_lines(path: Union[str, Path]) -> Iterator[RawLine]:
    """Boş olmayan satırları gerçek satır numaralarıyla üretir.

    Geçersiz UTF-8 baytları ve NUL karakterleri U+FFFD ile değiştirilir
    (PostgreSQL TEXT alanı NUL kabul etmez).
    """
    with open(path, encoding="utf-8", errors="replace", newline="\n") as f:
        for line_no, line in enumerate(f, start=1):
            text = line.rstrip("\r\n").replace("\x00", "�")
            if text.strip():
                yield RawLine(line_no, text)
