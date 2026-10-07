from src.etl.extract import RawLine, file_sha256, read_lines


def test_read_lines_skips_blank_and_keeps_line_numbers(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(b"first\r\n\n   \nfourth\n")
    assert list(read_lines(log)) == [RawLine(1, "first"), RawLine(4, "fourth")]


def test_read_lines_replaces_invalid_bytes_and_nul(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(b"ok \xff\xfe bytes\nnul\x00here\n")
    lines = list(read_lines(log))
    assert lines[0].text == "ok �� bytes"
    assert lines[1].text == "nul�here"


def test_file_sha256_depends_on_content(tmp_path):
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_text("same\n")
    b.write_text("same\n")
    assert file_sha256(a) == file_sha256(b)
    b.write_text("different\n")
    assert file_sha256(a) != file_sha256(b)
