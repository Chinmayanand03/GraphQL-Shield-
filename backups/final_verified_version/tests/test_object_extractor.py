import pytest
from app.security.object_extractor import normalize_query

def test_direct_query():
    query = """
    query {
        user(id: 101) {
            id
            username
        }
    }
    """
    result = normalize_query(query)
    assert result is not None
    assert result["operation"] == "query"
    assert len(result["objects"]) == 1
    assert result["objects"][0]["type"] == "User"
    assert result["objects"][0]["id"] == 101
    assert result["objects"][0]["path"] == "user"

def test_variable_query():
    query = """
    query GetResource($resId: Int!) {
        resource(id: $resId) {
            id
            name
        }
    }
    """
    variables = {"resId": 505}
    result = normalize_query(query, variables)
    assert result is not None
    assert result["operation"] == "query"
    assert len(result["objects"]) == 1
    assert result["objects"][0]["type"] == "Resource"
    assert result["objects"][0]["id"] == 505
    assert result["objects"][0]["path"] == "resource"

def test_nested_query():
    query = """
    query {
        user(id: 101) {
            username
            resource(id: 202) {
                name
            }
        }
    }
    """
    result = normalize_query(query)
    assert result is not None
    assert len(result["objects"]) == 2
    
    user_obj = next(o for o in result["objects"] if o["type"] == "User")
    assert user_obj["id"] == 101
    assert user_obj["path"] == "user"
    
    res_obj = next(o for o in result["objects"] if o["type"] == "Resource")
    assert res_obj["id"] == 202
    assert res_obj["path"] == "user.resource"

def test_fragment_query():
    query = """
    fragment UserParts on User {
        resource(id: 303) {
            name
        }
    }
    query {
        user(id: 101) {
            ...UserParts
        }
    }
    """
    result = normalize_query(query)
    assert result is not None
    assert len(result["objects"]) == 2
    
    res_obj = next(o for o in result["objects"] if o["type"] == "Resource")
    assert res_obj["id"] == 303
    assert res_obj["path"] == "user.resource"

def test_invalid_query():
    query = "query { user(id: ) { name } }"
    result = normalize_query(query)
    assert result is None

def test_unsupported_query_structure():
    # Introspection or queries without ID arguments
    query = """
    query {
        __schema {
            types {
                name
            }
        }
    }
    """
    result = normalize_query(query)
    assert result is not None
    assert len(result["objects"]) == 0
