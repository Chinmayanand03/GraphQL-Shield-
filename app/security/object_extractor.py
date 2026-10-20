from graphql import FieldNode, VariableNode, IntValueNode, StringValueNode, ListValueNode, OperationDefinitionNode, FragmentSpreadNode, FragmentDefinitionNode, InlineFragmentNode
from .graphql_parser import parse_query

def normalize_query(query: str, variables: dict = None) -> dict | None:
    """
    Analyzes GraphQL queries to identify operation type, fields, object IDs, and paths.
    Supports variables, nested queries, and basic fragments.
    
    Returns a normalized internal representation, e.g.:
    {
      "operation": "query",
      "objects": [
        {
          "type": "User",
          "id": 102,
          "path": "user"
        }
      ]
    }
    """
    ast = parse_query(query)
    if not ast:
        return None
        
    variables = variables or {}
    result = {
        "operation": None,
        "objects": []
    }
    
    fragments = {}
    expanding = set()  # guards against self-referencing fragment spreads
    
    # Pass 1: Collect fragments
    for definition in ast.definitions:
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition
            
    # Pass 2: Traverse operations and extract objects
    for definition in ast.definitions:
        if isinstance(definition, OperationDefinitionNode):
            result["operation"] = definition.operation.value
            
            def visit(node, current_path):
                if isinstance(node, FieldNode):
                    field_name = node.name.value
                    path = f"{current_path}.{field_name}" if current_path else field_name
                    
                    obj_ids = []
                    for arg in (node.arguments or ()):
                        if arg.name.value == "id":
                            value = arg.value
                            if isinstance(value, VariableNode):
                                value = variables.get(value.name.value)
                            elif isinstance(value, ListValueNode):
                                value = [v.value for v in value.values if hasattr(v, "value")]
                            elif isinstance(value, (IntValueNode, StringValueNode)):
                                value = value.value
                            else:
                                value = None
                            if isinstance(value, list):
                                obj_ids.extend(v for v in value if v is not None)
                            elif value is not None:
                                obj_ids.append(value)

                    for obj_id in obj_ids:
                        try:
                            obj_id = int(obj_id)
                        except (ValueError, TypeError):
                            pass

                        # Infer object type directly from field name for this prototype
                        inferred_type = "User" if field_name.lower() == "user" else field_name.capitalize()

                        result["objects"].append({
                            "type": inferred_type,
                            "id": obj_id,
                            "path": path
                        })
                        
                    if node.selection_set:
                        for selection in node.selection_set.selections:
                            visit(selection, path)
                            
                elif isinstance(node, InlineFragmentNode):
                    # `... on Query { user(id: 102) { ... } }` must be inspected like any other selection.
                    if node.selection_set:
                        for selection in node.selection_set.selections:
                            visit(selection, current_path)

                elif isinstance(node, FragmentSpreadNode):
                    frag_name = node.name.value
                    if frag_name in fragments and frag_name not in expanding:
                        fragment = fragments[frag_name]
                        if fragment.selection_set:
                            expanding.add(frag_name)
                            for selection in fragment.selection_set.selections:
                                visit(selection, current_path)
                            expanding.discard(frag_name)

            if definition.selection_set:
                for selection in definition.selection_set.selections:
                    visit(selection, "")
                    
    return result

def extract_resource_id(query: str, variables: dict = None) -> int | None:
    """Backward compatibility helper to find the first Resource ID."""
    normalized = normalize_query(query, variables)
    if not normalized:
        return None
        
    for obj in normalized["objects"]:
        if obj["type"].lower() == "resource":
            return obj["id"]
            
    return None
