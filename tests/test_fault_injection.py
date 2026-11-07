"""The fault-injection experiment must keep matching the code it patches."""
import random

import pytest
from graphql import parse, validate

from app.graphql.schema import schema
from scripts.run_fault_injection import FAULTS, compose_request, patched_source

WORLD = {"owner": {101: 101, 102: 102, 201: 101, 301: 102}, "folders": [201, 301], "documents": [101, 102]}


@pytest.mark.parametrize("name", FAULTS)
def test_fault_still_applies_and_compiles(name):
    path, old, new, _ = FAULTS[name]
    compile(patched_source(path, old, new), path, "exec")


def test_composed_requests_are_valid_graphql():
    rng = random.Random(7)
    for _ in range(400):
        _, body = compose_request(rng, WORLD, 101)
        for operation in body if isinstance(body, list) else [body]:
            errors = validate(schema._schema, parse(operation["query"]))
            assert errors == [], operation["query"]
