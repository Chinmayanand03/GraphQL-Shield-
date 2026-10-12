from graphql import FieldNode, VariableNode, IntValueNode, StringValueNode, OperationDefinitionNode, FragmentSpreadNode, FragmentDefinitionNode
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
                    
                    obj_id = None
                    for arg in (node.arguments or ()):
                        if arg.name.value == "id":
                            if isinstance(arg.value, VariableNode):
                                var_name = arg.value.name.value
                                obj_id = variables.get(var_name)
                            elif isinstance(arg.value, (IntValueNode, StringValueNode)):
                                obj_id = arg.value.value
                                
                    if obj_id is not None:
                        try:
                            obj_id = int(obj_id)
                        except (ValueError, TypeError):
                            pass
                            
                        # Infer object type directly from field name for this prototype
                        inferred_type = field_name.capitalize()
                        
                        result["objects"].append({
                            "type": inferred_type,
                            "id": obj_id,
                            "path": path
                        })
                        
                    if node.selection_set:
                        for selection in node.selection_set.selections:
                            visit(selection, path)
                            
                elif isinstance(node, FragmentSpreadNode):
                    frag_name = node.name.value
                    if frag_name in fragments:
                        fragment = fragments[frag_name]
                        if fragment.selection_set:
                            for selection in fragment.selection_set.selections:
                                visit(selection, current_path)

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
