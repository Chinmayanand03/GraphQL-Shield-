"""
Clinic records GraphQL API: schema-first SDL on plain graphql-core, with dict
resolvers and Relay global IDs. It shares no code with the Strawberry demo.

Like the demo application, the resolvers deliberately contain NO ownership
checks: they are the BOLA baseline. Protection comes only from GraphQL Shield,
configured for this application by CLINIC_CONFIG:

  POST /clinic/graphql           Layer 1 (enforce_request) + Layer 2 (OwnershipMiddleware)
  POST /clinic/graphql-insecure  no protection; benchmark baseline only
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from graphql import build_schema, graphql

from app.config import settings
from app.core.dependencies import get_current_user
from app.database import get_db_connection
from app.security.enforcement import enforce_request
from app.security.runtime_object_guard import OwnershipMiddleware
from app.security.shield_config import ShieldConfig

from .data import from_global_id, init_clinic, owner_of, raw_id, to_global_id

SDL = """
type Patient {
  id: ID!
  name: String!
  records: [Record!]!
}

type Record {
  id: ID!
  diagnosis: String!
  patient: Patient
  prescriptions: [Prescription!]!
}

type Prescription {
  id: ID!
  drug: String!
  record: Record
}

type Query {
  patient(id: ID!): Patient
  record(id: ID!): Record
  prescription(id: ID!): Prescription
  myPatients: [Patient!]!
}

type Mutation {
  updateRecord(id: ID!, diagnosis: String!): Record
  createRecord(patientId: ID!, diagnosis: String!): Record
  deletePrescription(id: ID!): Boolean!
}
"""


def _rows(sql: str, params: tuple = ()) -> list[dict]:
    conn = get_db_connection()
    try:
        return [dict(row) for row in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _one(sql: str, params: tuple = ()) -> dict | None:
    rows = _rows(sql, params)
    return rows[0] if rows else None


def _write(sql: str, params: tuple = ()) -> int:
    conn = get_db_connection()
    try:
        cursor = conn.execute(sql, params)
        conn.commit()
        return cursor.lastrowid if sql.lstrip().upper().startswith("INSERT") else cursor.rowcount
    finally:
        conn.close()


schema = build_schema(SDL)


def field(type_name: str, field_name: str):
    """Bind a resolver to a field of the SDL schema."""
    def bind(resolver):
        schema.get_type(type_name).fields[field_name].resolve = resolver
        return resolver
    return bind


@field("Query", "patient")
def resolve_patient(_, info, id):
    return _one("SELECT * FROM clinic_patients WHERE id = ?", (raw_id(id),))


@field("Query", "record")
def resolve_record(_, info, id):
    return _one("SELECT * FROM clinic_records WHERE id = ?", (raw_id(id),))


@field("Query", "prescription")
def resolve_prescription(_, info, id):
    return _one("SELECT * FROM clinic_prescriptions WHERE id = ?", (raw_id(id),))


@field("Query", "myPatients")
def resolve_my_patients(_, info):
    user = info.context["request"].state.current_user
    return _rows("SELECT * FROM clinic_patients WHERE doctor_id = ?", (user["user_id"],))


@field("Patient", "id")
def resolve_patient_id(patient, info):
    return to_global_id("Patient", patient["id"])


@field("Patient", "records")
def resolve_patient_records(patient, info):
    return _rows("SELECT * FROM clinic_records WHERE patient_id = ?", (patient["id"],))


@field("Record", "id")
def resolve_record_id(record, info):
    return to_global_id("Record", record["id"])


@field("Record", "patient")
def resolve_record_patient(record, info):
    return _one("SELECT * FROM clinic_patients WHERE id = ?", (record["patient_id"],))


@field("Record", "prescriptions")
def resolve_record_prescriptions(record, info):
    return _rows("SELECT * FROM clinic_prescriptions WHERE record_id = ?", (record["id"],))


@field("Prescription", "id")
def resolve_prescription_id(prescription, info):
    return to_global_id("Prescription", prescription["id"])


@field("Prescription", "record")
def resolve_prescription_record(prescription, info):
    return _one("SELECT * FROM clinic_records WHERE id = ?", (prescription["record_id"],))


@field("Mutation", "updateRecord")
def resolve_update_record(_, info, id, diagnosis):
    _write("UPDATE clinic_records SET diagnosis = ? WHERE id = ?", (diagnosis, raw_id(id)))
    return _one("SELECT * FROM clinic_records WHERE id = ?", (raw_id(id),))


@field("Mutation", "createRecord")
def resolve_create_record(_, info, patientId, diagnosis):
    user = info.context["request"].state.current_user
    new_id = _write("INSERT INTO clinic_records (patient_id, owner_id, diagnosis) VALUES (?, ?, ?)",
                    (raw_id(patientId), user["user_id"], diagnosis))
    return _one("SELECT * FROM clinic_records WHERE id = ?", (new_id,))


@field("Mutation", "deletePrescription")
def resolve_delete_prescription(_, info, id):
    return _write("DELETE FROM clinic_prescriptions WHERE id = ?", (raw_id(id),)) > 0


CLINIC_CONFIG = ShieldConfig(
    schema=lambda: schema,
    owned_types={"Patient": "Patient", "Record": "Record", "Prescription": "Prescription"},
    owner_lookup=owner_of,
    # createRecord changes a patient's chart; its return type (Record) does not say
    # which patient, so the target comes from the registry. deletePrescription
    # returns Boolean. updateRecord is derived from the schema.
    mutation_targets={
        "createRecord": ("patientId", "Patient"),
        "deletePrescription": ("id", "Prescription"),
    },
    decode_id=from_global_id,
    protected_paths=("/clinic/graphql",),
)

router = APIRouter(prefix="/clinic", tags=["clinic"])


async def _execute(request: Request, middleware: list) -> JSONResponse:
    data = await request.json()
    operations = data if isinstance(data, list) else [data]
    if len(operations) > settings.MAX_BATCH_OPERATIONS:
        raise HTTPException(status_code=400, detail={"error": "BATCH_SIZE_EXCEEDED"})
    results = []
    for operation in operations:
        result = await graphql(
            schema,
            operation.get("query", ""),
            variable_values=operation.get("variables"),
            operation_name=operation.get("operationName"),
            context_value={"request": request},
            middleware=middleware,
        )
        payload = {"data": result.data}
        if result.errors:
            payload["errors"] = [error.formatted for error in result.errors]
        results.append(payload)
    return JSONResponse(results if isinstance(data, list) else results[0])


@router.post("/graphql")
async def clinic_graphql(request: Request, current_user: dict = Depends(get_current_user)):
    """Protected clinic endpoint: Layer 1 before execution, Layer 2 during it."""
    await enforce_request(request, current_user, CLINIC_CONFIG)
    return await _execute(request, [OwnershipMiddleware(CLINIC_CONFIG)])


@router.post("/graphql-insecure")
async def clinic_graphql_insecure(request: Request, current_user: dict = Depends(get_current_user)):
    """Vulnerable clinic baseline for comparison; off unless ENABLE_INSECURE_BASELINE."""
    if not settings.ENABLE_INSECURE_BASELINE:
        raise HTTPException(status_code=404, detail="Insecure benchmark baseline is disabled")
    request.state.current_user = current_user
    return await _execute(request, [])


__all__ = ["router", "schema", "CLINIC_CONFIG", "init_clinic"]
