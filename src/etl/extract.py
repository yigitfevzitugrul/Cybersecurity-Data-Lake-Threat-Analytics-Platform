"""Extract: ham log dosyasını okur."""
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Union


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
