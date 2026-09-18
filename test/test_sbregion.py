"""Tests for SbRegion.Dat rung-text parsing, specifically the source-protected
("encoded") AddOnInstruction case: a protected AOI's rungs are still stored
as SbRegion.Dat "Rung NT"/"REGION NT" records, but the payload is ciphertext,
not UTF-16 ladder text.

Real file: HMPS13287_210312.ACD (RSLogix 5000 v33.00), contains two
source-protected AddOnInstructions, both exported by Studio 5000 itself as
opaque <EncodedData> blocks. Decoding one of the protected rungs as UTF-16
raised UnicodeDecodeError and aborted the entire file's conversion, even
though every other routine in the project is perfectly readable.

Verified against real ground truth (a Studio 5000 "RLL Scrap" clipboard
export of the actual protected logic, obtained by the file's owner, who has
legitimate access to view/export -- but not edit -- this AOI): one of the two
protected AOIs turned out to have its rung text stored in the clear despite
being marked "encoded" (the ciphertext lives elsewhere, apparently a
tamper-evidence/signature blob rather than the logic itself) -- our decode
recovers it byte-for-byte correctly. The other AOI's rungs are genuinely
ciphertext, but some of that ciphertext happens to be valid UTF-16 that
doesn't raise UnicodeDecodeError -- it just decodes to non-ASCII noise
(Unicode Private Use Area characters, CJK/Hangul garbage, embedded nulls).
Tag and instruction syntax is always ASCII, so an `isascii()` check on top of
the decode is needed to reject that case too, or it would silently fabricate
fake "logic" out of still-encrypted bytes instead of just omitting the rung.
"""
import sqlite3
import struct

import pytest

from acd.record.sbregion import SbRegionRecord


class _FakeRecordBuffer:
    def __init__(self, record_buffer):
        self.record_buffer = record_buffer


class _FakeDatRecord:
    """Minimal stand-in for a Dat.Record: SbRegionRecord only ever touches
    .identifier and .record.record_buffer."""

    def __init__(self, identifier, record_buffer):
        self.identifier = identifier
        self.record = _FakeRecordBuffer(record_buffer)


def _fafa_sbregion_bytes(language_type: str, payload: bytes, identifier: int = 1) -> bytes:
    # Layout (see resources/templates/SbRegion/FAFA_SbRegion.ksy):
    #   record_length: u4, header{sb_regions: u2, identifier: u4,
    #   language_type: strz size=41}, len_record_buffer: u4, record_buffer.
    header = (
        struct.pack("<H", 0)
        + struct.pack("<I", identifier)
        + language_type.encode("utf-8").ljust(41, b"\x00")
    )
    body = header + struct.pack("<I", len(payload)) + payload
    return struct.pack("<I", len(body) + 4) + body


# A single unpaired UTF-16 low-surrogate code unit (0xDC00, little-endian) --
# not decodable by any strict UTF-16 decoder, and exactly the shape of the
# byte noise found in HMPS13287_210312.ACD's protected-AOI rung records.
_UNDECODABLE_PAYLOAD = b"\x00\xdc"

# Ciphertext that happens to decode as *valid* (but non-ASCII) UTF-16 --
# no UnicodeDecodeError, so it must be caught by the isascii() check instead.
# Matches the real shape found: CJK/Hangul-range code units plus an embedded
# null, none of it valid ladder/tag syntax.
_DECODABLE_BUT_NON_ASCII_PAYLOAD = "꩎ꪖЊ\x00嶠楕ൕ".encode("utf-16-le")


def _database():
    database = sqlite3.connect(":memory:")
    cursor = database.cursor()
    cursor.execute(
        "CREATE TABLE comps(object_id int, parent_id int, comp_name text, "
        "seq_number int, record_type int, record BLOB NOT NULL)"
    )
    cursor.execute("CREATE TABLE rungs(object_id int, text text, unused text)")
    return database, cursor


def test_parse_skips_undecodable_protected_rung_instead_of_raising():
    dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", _UNDECODABLE_PAYLOAD))
    assert SbRegionRecord.parse(dat_record, name_lookup={}) is None


def test_parse_rejects_decodable_but_non_ascii_ciphertext():
    dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", _DECODABLE_BUT_NON_ASCII_PAYLOAD))
    assert SbRegionRecord.parse(dat_record, name_lookup={}) is None


def test_parse_still_returns_normal_rung_text():
    payload = "XIC(Start)OTE(Motor)".encode("utf-16-le")
    dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", payload, identifier=42))
    result = SbRegionRecord.parse(dat_record, name_lookup={})
    assert result == (42, "XIC(Start)OTE(Motor)", "")


def test_post_init_skips_undecodable_protected_rung_instead_of_raising():
    database, cursor = _database()
    try:
        dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", _UNDECODABLE_PAYLOAD))
        # Must not raise UnicodeDecodeError.
        SbRegionRecord(cursor, dat_record)
        cursor.execute("SELECT * FROM rungs")
        assert cursor.fetchall() == []
    finally:
        database.close()


def test_post_init_rejects_decodable_but_non_ascii_ciphertext():
    database, cursor = _database()
    try:
        dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", _DECODABLE_BUT_NON_ASCII_PAYLOAD))
        # Must not raise, and must not insert the non-ASCII noise as a rung.
        SbRegionRecord(cursor, dat_record)
        cursor.execute("SELECT * FROM rungs")
        assert cursor.fetchall() == []
    finally:
        database.close()


def test_post_init_still_inserts_normal_rung_text():
    database, cursor = _database()
    try:
        payload = "XIC(Start)OTE(Motor)".encode("utf-16-le")
        dat_record = _FakeDatRecord(64250, _fafa_sbregion_bytes("Rung NT", payload, identifier=99))
        SbRegionRecord(cursor, dat_record)
        cursor.execute("SELECT * FROM rungs")
        assert cursor.fetchall() == [(99, "XIC(Start)OTE(Motor)", "")]
    finally:
        database.close()
