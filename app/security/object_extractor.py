from graphql import FieldNode, VariableNode, ListValueNode, OperationDefinitionNode, FragmentSpreadNode, FragmentDefinitionNode, InlineFragmentNode, value_from_ast_untyped
from .graphql_parser import parse_query
from .shield_config import ShieldConfig, default_config, unwrap_type


def _legacy_key(field_name: str) -> str:
    """Fallback for fields the schema does not know (e.g. unit tests without a
    schema): `user` targets a User, every other id-taking field a Resource."""
    return "User" if field_name.lower() == "user" else "Resource"


def normalize_query(query: str, variables: dict = None, config: ShieldConfig | None = None) -> dict | None:
    """
    Layer 1 view of a request: operation type and every owned object ID it names.

    Schema-aware: each ID's object type comes from the schema (the type the field
    returns, or the mutation's registered target), not from the field name. IDs
    are decoded through the config, so a Relay global ID such as
    base64("Resource:102") yields both its embedded type and its raw ID.
    Supports variables (and their declared defaults), nested fields, aliases,
    named and inline fragments.

    Returns e.g. {"operation": "query", "objects": [{"type": "User", "id": 102, "path": "user"}]}
    """
    ast = parse_query(query)
    if not ast:
        return None

    config = config or default_config()
    try:
        schema = config.graphql_schema()
    except Exception:
        schema = None
    variables = variables or {}
    result = {
        "operation": None,
        "objects": []
    }

    fragments = {d.name.value: d for d in ast.definitions if isinstance(d, FragmentDefinitionNode)}
    expanding = set()  # guards against self-referencing fragment spreads

    def schema_type(name):
        return schema.get_type(name) if schema is not None and name else None

    for definition in ast.definitions:
        if not isinstance(definition, OperationDefinitionNode):
            continue
        operation = definition.operation.value
        result["operation"] = operation
        root_type = None
        if schema is not None:
            root_type = {"query": schema.query_type, "mutation": schema.mutation_type,
                         "subscription": schema.subscription_type}.get(operation)
        # A variable the client did not send takes its declared default, e.g.
        # `query($id: Int = 102)`. Found by the blind-spot predictor's discovery run.
        defaults = {
            var.variable.name.value: value_from_ast_untyped(var.default_value)
            for var in (definition.variable_definitions or ())
            if var.default_value is not None
        }

        def argument_values(node, argument):
            values = []
            for arg in (node.arguments or ()):
                if arg.name.value != argument:
                    continue
                value = arg.value
                if isinstance(value, VariableNode):
                    name = value.name.value
                    value = variables[name] if name in variables else defaults.get(name)
                elif isinstance(value, ListValueNode):
                    value = [value_from_ast_untyped(v) for v in value.values]
                else:
                    value = value_from_ast_untyped(value)
                if isinstance(value, list):
                    values.extend(v for v in value if v is not None)
                elif value is not None:
                    values.append(value)
            return values

        def add_object(key, raw_value, path):
            embedded_key, raw_id = config.decode(raw_value)
            try:
                raw_id = int(raw_id)
            except (ValueError, TypeError):
                pass
            # An ID that names a different type than the field expects (type
            # confusion, cf. CVE-2022-39275) is checked as both types.
            for object_key in dict.fromkeys(k for k in (key, embedded_key) if k):
                result["objects"].append({"type": object_key, "id": raw_id, "path": path})

        def visit(node, parent_type, current_path, is_root):
            if isinstance(node, FieldNode):
                field_name = node.name.value
                path = f"{current_path}.{field_name}" if current_path else field_name
                field_def = config.field_definition(parent_type, field_name)

                if field_def is None:
                    targets = [(argument, _legacy_key(field_name)) for argument in config.id_arguments]
                    child_type = None
                else:
                    if is_root and operation == "mutation":
                        target = config.mutation_target(field_name, field_def)
                        targets = [target] if target else []
                    else:
                        key = config.owned_key(field_def.type)
                        targets = [(argument, key) for argument in config.id_arguments if key and argument in field_def.args]
                    child_type, _ = unwrap_type(field_def.type)

                for argument, key in targets:
                    for value in argument_values(node, argument):
                        add_object(key, value, path)

                if node.selection_set:
                    for selection in node.selection_set.selections:
                        visit(selection, child_type, path, False)

            elif isinstance(node, InlineFragmentNode):
                # `... on Query { user(id: 102) { ... } }` must be inspected like any other selection.
                fragment_type = schema_type(node.type_condition.name.value) if node.type_condition else parent_type
                for selection in node.selection_set.selections:
                    visit(selection, fragment_type, current_path, is_root)

            elif isinstance(node, FragmentSpreadNode):
                frag_name = node.name.value
                if frag_name in fragments and frag_name not in expanding:
                    fragment = fragments[frag_name]
                    expanding.add(frag_name)
                    for selection in fragment.selection_set.selections:
                        visit(selection, schema_type(fragment.type_condition.name.value), current_path, is_root)
                    expanding.discard(frag_name)

        for selection in definition.selection_set.selections:
            visit(selection, root_type, "", True)

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
