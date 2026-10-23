import json
import logging
from fastapi import Request, HTTPException, Depends
from app.config import settings
from app.core.dependencies import get_current_user
from .object_extractor import normalize_query
from .ownership import get_object_owner
from .shield_config import ShieldConfig
from .authorization import AuthorizationContext, PolicyEngine
from .audit import log_decision
from .layers import (
    EVENT_BLIND_SPOT_PREDICTED,
    EVENT_L1_BLOCKED,
    is_enabled,
    mark_layer1_checked,
    record_layer_event,
)

logger = logging.getLogger(__name__)

policy_engine = PolicyEngine()

async def bola_enforcement_middleware(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Layer 1: centralized pre-execution gate.
    Runs BEFORE the GraphQL backend, blocking BOLA attacks at the edge.
    Layer 2 (runtime_object_guard) re-checks everything at execution time, so a
    query shape this gate cannot parse is still never answered with foreign objects.
    """
    await enforce_request(request, current_user)


async def enforce_request(request: Request, current_user: dict, config: ShieldConfig | None = None) -> None:
    """Layer 1 for any application: `config` describes its schema and ownership
    (None means this repository's application). Raises HTTPException(403) on BOLA."""
    request.state.current_user = current_user
    request.state.layer1_checked = set()

    if not is_enabled("layer1"):
        return

    # Queries over GET are disabled on the protected router (allow_queries_via_get=False).
    if request.method != "POST":
        return

    try:
        body = await request.body()
        data = json.loads(body)
    except Exception:
        # Fail closed: a body this gate cannot read is not forwarded unchecked.
        raise HTTPException(status_code=400, detail={"error": "MALFORMED_REQUEST", "reason": "Request body is not valid JSON."})

    # Query batching: a JSON array of operations is checked operation by operation.
    if isinstance(data, list):
        if len(data) > settings.MAX_BATCH_OPERATIONS:
            raise HTTPException(
                status_code=400,
                detail={"error": "BATCH_SIZE_EXCEEDED",
                        "reason": f"At most {settings.MAX_BATCH_OPERATIONS} operations per batch, received {len(data)}."},
            )
        for index, operation in enumerate(data):
            if not isinstance(operation, dict):
                raise HTTPException(status_code=400, detail={"error": "MALFORMED_REQUEST", "batch_index": index})
            _enforce_operation(request, current_user, operation, batch_index=index, config=config)
        if config is None:
            _predict_blind_spot(request, current_user, data)
        return

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail={"error": "MALFORMED_REQUEST", "reason": "Expected a JSON object or array."})

    _enforce_operation(request, current_user, data, config=config)
    # The blind-spot model is trained on this repository's application only.
    if config is None:
        _predict_blind_spot(request, current_user, [data])


def _predict_blind_spot(request: Request, current_user: dict, operations: list[dict]) -> None:
    """Advisory: score a request Layer 1 allowed with the blind-spot predictor.

    The prediction is stored on the request and recorded as an event when positive;
    it never changes the authorization decision (Layer 2 still checks everything).
    """
    try:
        from .blind_spot_model import score_request

        result = score_request(operations, caller_is_admin=str(current_user.get("role", "")).upper() == "ADMIN")
    except Exception:
        logger.debug("Blind-spot prediction skipped", exc_info=True)
        return
    if not result or result["probability"] is None:
        return
    request.state.blind_spot_probability = result["probability"]
    if result["prediction"]:
        record_layer_event(current_user.get("user_id"), "L1", EVENT_BLIND_SPOT_PREDICTED,
                           detail=f"p={result['probability']:.2f}")


def _enforce_operation(request: Request, current_user: dict, data: dict, batch_index: int | None = None,
                       config: ShieldConfig | None = None) -> None:
    query = data.get("query", "")
    variables = data.get("variables") or {}

    normalized = normalize_query(query, variables if isinstance(variables, dict) else {}, config=config)
    owner_lookup = config.owner_lookup if config is not None else get_object_owner
    
    if not normalized or not normalized["objects"]:
        return

    user_id = current_user.get("user_id")
    role = current_user.get("role", "user")
    
    # Phase 6: Contextual Policy Evaluation
    for obj in normalized["objects"]:
        object_id = obj["id"]
        object_type = obj["type"]
        path = obj["path"]
        
        # Look up true ownership
        owner_id = owner_lookup(object_type, object_id)
        mark_layer1_checked(request, object_type, object_id)
        
        # Assemble structured context
        context = AuthorizationContext(
            user_id=user_id,
            role=role,
            operation=normalized["operation"] or "query",
            object_type=object_type,
            object_id=object_id,
            path=path,
            owner_id=owner_id,
            metadata={"client_host": request.client.host if request.client else "unknown"}
        )
        
        # Evaluate policy engine rules
        result = policy_engine.evaluate(context)
        
        logger.info(
            "Layer 1 decision user_id=%s role=%s path=%s object=%s:%s owner=%s decision=%s reason=%s risk=%s(%s)",
            user_id, role.upper(), path, object_type, object_id, owner_id,
            result["decision"], result["reason"], result["risk_level"], result["risk_score"],
        )

        # Audit log the decision
        log_decision(
            user_id=user_id,
            role=role,
            operation=context.operation,
            object_type=object_type,
            object_id=object_id,
            path=path,
            decision=result["decision"],
            reason=result["reason"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            layer="L1",
        )
        
        # Enforcement Block
        if result["decision"] == "DENY":
            record_layer_event(user_id, "L1", EVENT_L1_BLOCKED, object_type, object_id, path,
                               result["reason"] if batch_index is None else f"{result['reason']} (batch index {batch_index})")
            raise HTTPException(
                status_code=403, 
                detail={
                    "layer": "L1_PRE_EXECUTION",
                    "batch_index": batch_index,
                    "decision": result["decision"],
                    "user_id": user_id,
                    "object_id": object_id,
                    "reason": result["reason"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"]
                }
            )
