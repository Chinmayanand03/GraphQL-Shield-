from graphql import parse

def parse_query(query: str):
    """
    Parses a GraphQL query string into an Abstract Syntax Tree (AST).
    Returns None if the query is invalid.
    """
    try:
        return parse(query)
    except Exception:
        return None
