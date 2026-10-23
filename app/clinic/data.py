"""Clinic tables, seed data and the trusted owner lookup.

Doctors are the demo users (101-104). A patient belongs to one doctor, but
records and prescriptions have their own owner: a colleague can add a record
to someone else's patient. Owning a patient therefore does not grant access to
every record under it, which is the relationship-BOLA case.
"""
from __future__ import annotations

import base64
from typing import Any

from app.database import get_db_connection

TABLES = {
    # ownership key -> (table, owner column)
    "Patient": ("clinic_patients", "doctor_id"),
    "Record": ("clinic_records", "owner_id"),
    "Prescription": ("clinic_prescriptions", "owner_id"),
}

PATIENTS = [(1, "Asha Rao", 101), (2, "Vikram Nair", 102), (3, "Meena Iyer", 103)]
RECORDS = [  # (id, patient_id, owner_id, diagnosis)
    (11, 1, 101, "Seasonal allergy"),
    (12, 1, 102, "Cardiology second opinion"),   # colleague's record on doctor 101's patient
    (21, 2, 102, "Hypertension"),
    (31, 3, 103, "Migraine"),
]
PRESCRIPTIONS = [  # (id, record_id, owner_id, drug)
    (111, 11, 101, "Cetirizine"),
    (112, 11, 103, "Prednisolone"),               # another doctor's prescription on record 11
    (211, 21, 102, "Amlodipine"),
    (311, 31, 103, "Sumatriptan"),
]


def init_clinic(reset: bool = False) -> None:
    conn = get_db_connection()
    try:
        if reset:
            for table in ("clinic_prescriptions", "clinic_records", "clinic_patients"):
                conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.execute("CREATE TABLE IF NOT EXISTS clinic_patients (id INTEGER PRIMARY KEY, name TEXT NOT NULL, doctor_id INTEGER NOT NULL)")
        conn.execute("""CREATE TABLE IF NOT EXISTS clinic_records (
            id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, diagnosis TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS clinic_prescriptions (
            id INTEGER PRIMARY KEY, record_id INTEGER NOT NULL, owner_id INTEGER NOT NULL, drug TEXT NOT NULL)""")
        if conn.execute("SELECT COUNT(*) FROM clinic_patients").fetchone()[0] == 0:
            conn.executemany("INSERT INTO clinic_patients VALUES (?, ?, ?)", PATIENTS)
            conn.executemany("INSERT INTO clinic_records VALUES (?, ?, ?, ?)", RECORDS)
            conn.executemany("INSERT INTO clinic_prescriptions VALUES (?, ?, ?, ?)", PRESCRIPTIONS)
        conn.commit()
    finally:
        conn.close()


def owner_of(key: str, object_id: Any) -> Any:
    """Trusted owner lookup for the clinic's owned types."""
    if key not in TABLES:
        return None
    table, column = TABLES[key]
    conn = get_db_connection()
    try:
        row = conn.execute(f"SELECT {column} FROM {table} WHERE id = ?", (object_id,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def to_global_id(type_name: str, raw_id: int) -> str:
    return base64.b64encode(f"{type_name}:{raw_id}".encode()).decode()


def from_global_id(value: Any) -> tuple[str | None, Any]:
    """Relay global ID -> (type name, raw id). Anything else passes through."""
    try:
        type_name, raw_id = base64.b64decode(str(value), validate=True).decode().split(":", 1)
        if type_name in TABLES:
            return type_name, int(raw_id)
    except Exception:
        pass
    return None, value


def raw_id(value: Any) -> Any:
    _, decoded = from_global_id(value)
    try:
        return int(decoded)
    except (TypeError, ValueError):
        return decoded
