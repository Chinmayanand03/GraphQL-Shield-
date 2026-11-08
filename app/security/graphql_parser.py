from functools import lru_cache

from graphql import parse


@lru_cache(maxsize=1024)
def parse_query(query: str):
    """
    Parses a GraphQL query string into an Abstract Syntax Tree (AST).
    Returns None if the query is invalid.

    Layer 1 and the blind-spot features both parse each request, and clients send
    the same query text again and again, so parsed documents are cached. Callers
    only read the tree; none may modify it.
    """
    try:
        return parse(query)
    except Exception:
        return None
