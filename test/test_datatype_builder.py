"""Tests for DataTypeBuilder handling a data type record that is missing its
0x6C/0x67/0x69 extended attributes -- observed on a UDT nested inside a
source-protected ("encoded") AddOnInstruction (HMPS13287_210312.ACD,
RSLogix 5000 v33.00): Rockwell withholds some of a protected AOI's own
metadata alongside its encrypted logic, so these attributes that are
"normally always present" are simply absent for that one type record.
"""
import sqlite3
import struct

from acd.l5x.elements import DataTypeBuilder


def _legacy_rx(*, cip_type=0x6B, object_id=100, attributes=()):
    raw = bytearray(32)
    struct.pack_into("<II", raw, 0, 0, 0x12345678)
    struct.pack_into("<HH", raw, 8, cip_type, 0)
    struct.pack_into("<I", raw, 16, 0)
    struct.pack_into("<I", raw, 20, object_id)
    struct.pack_into("<I", raw, 28, len(attributes))
    for attribute_id, value in attributes:
        raw.extend(struct.pack("<II", attribute_id, len(value)))
        raw.extend(value)
    struct.pack_into("<I", raw, 24, len(raw) - 28)
    return bytes(raw)


def _database():
    database = sqlite3.connect(":memory:")
    cursor = database.cursor()
    cursor.execute(
        "CREATE TABLE comps(object_id int, parent_id int, comp_name text, "
        "seq_number int, record_type int, record BLOB NOT NULL)"
    )
    cursor.execute(
        "CREATE TABLE comments(seq_number int, sub_record_length int, "
        "object_id int, record_string text, record_type int, parent int, "
        "tag_reference text, rung_content int, member_ref int)"
    )
    return database, cursor


def _insert(cursor, object_id, name, record, parent_id=0):
    cursor.execute(
        "INSERT INTO comps VALUES (?, ?, ?, ?, ?, ?)",
        (object_id, parent_id, name, 0, 256, record),
    )


def test_missing_string_family_and_class_attributes_default_instead_of_raising():
    # Only 0x64 (member_count) is present; 0x6C/0x67/0x69 are absent, as seen
    # on a data type nested in a protected AOI. Must not raise KeyError.
    database, cursor = _database()
    try:
        _insert(
            cursor,
            100,
            "ProtectedAoiLocalType",
            _legacy_rx(attributes=[(0x64, struct.pack("<I", 0))]),
        )

        data_type = DataTypeBuilder(cursor, 100).build()

        assert data_type.name == "ProtectedAoiLocalType"
        assert data_type.family == "NoFamily"
        assert data_type.cls == "User"
    finally:
        database.close()


def test_present_string_family_and_class_attributes_still_resolve():
    # Regression guard: when the attributes ARE present, behaviour is
    # unchanged from before the .get(...) defaulting was added.
    database, cursor = _database()
    try:
        _insert(
            cursor,
            100,
            "NormalUdt",
            _legacy_rx(
                attributes=[
                    (0x64, struct.pack("<I", 0)),
                    (0x6C, struct.pack("<I", 1)),  # StringFamily
                    (0x67, struct.pack("<I", 0)),
                    (0x69, struct.pack("<I", 1)),  # module_defined -> IO
                ]
            ),
        )

        data_type = DataTypeBuilder(cursor, 100).build()

        assert data_type.family == "StringFamily"
        assert data_type.cls == "IO"
    finally:
        database.close()
