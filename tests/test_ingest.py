from pathlib import Path
import tempfile
from wardguard.ingest.decode import decode
from wardguard.ingest.sniff import sniff
from wardguard.ingest.readers import load_all


def test_decode_utf8():
    raw = "Hello, world!".encode("utf-8")
    res = decode(raw)
    assert res is not None
    assert res[0] == "Hello, world!"
    assert res[1] == "utf-8"


def test_decode_bom():
    raw = b"\xef\xbb\xbfName,Age\nRaj,30"
    res = decode(raw)
    assert res is not None
    assert res[1] == "utf-8-sig"
    assert "Raj" in res[0]


def test_sniff_format():
    assert sniff(b'{"name": "test"}', "f.json") == "json"
    assert sniff(b'{"resourceType": "Patient"}', "p.json") == "fhir"
    assert sniff(b"a,b,c\n1,2,3", "data.csv") == "csv"
    assert sniff(b"a\tb\tc\n1\t2\t3", "data.tsv") == "tsv"
    assert sniff(b"Some plain text note", "note.txt") == "text"


def test_load_all_quarantine():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        (p / "bad.bin").write_bytes(b"\x00\x01\x02\xff\xfe\x00")
        files = load_all(p)
        assert len(files) == 1
        assert files[0].status == "quarantined"
