from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path

ROOT = Path.cwd()
MAIN = ROOT / "app" / "main.py"
DASHBOARD = ROOT / "app" / "static" / "dashboard.html"
SOURCE_MODULE = Path(__file__).parent / "payload" / "app" / "security" / "taint_request_explainer.py"
TEST_SOURCE = Path(__file__).parent / "tests" / "test_taint_request_explainer.py"

CSS_MARKER = "/* REQUEST_SPECIFIC_TAINT_TRACE_CSS_BEGIN */"
HTML_MARKER = "<!-- REQUEST_SPECIFIC_TAINT_TRACE_PANEL_BEGIN -->"
JS_MARKER = "// REQUEST_SPECIFIC_TAINT_TRACE_JS_BEGIN"
ROUTER_IMPORT = "from app.security.taint_request_explainer import router as taint_explainer_router"
ROUTER_INCLUDE = "app.include_router(taint_explainer_router)"

CSS = r'''/* REQUEST_SPECIFIC_TAINT_TRACE_CSS_BEGIN */
    .request-explanation { border:1px solid var(--line); background:linear-gradient(145deg,rgba(21,34,56,.94),rgba(16,26,43,.94)); border-radius:14px; padding:16px; margin-top:15px; }
    .request-explanation-head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:8px; }
    .request-explanation-title { font-size:13px; font-weight:850; }
    .request-explanation-subtitle { color:var(--muted); font-size:11px; margin-top:4px; }
    .trace-outcome { border:1px solid var(--line); border-radius:999px; padding:5px 9px; font-size:10px; font-weight:850; white-space:nowrap; }
    .trace-outcome.allowed { color:var(--green); border-color:rgba(67,214,160,.35); background:rgba(67,214,160,.08); }
    .trace-outcome.denied { color:var(--red); border-color:rgba(255,113,133,.35); background:rgba(255,113,133,.08); }
    .trace-outcome.warning { color:var(--amber); border-color:rgba(255,198,109,.35); background:rgba(255,198,109,.08); }
    .trace-flow { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:10px; margin-top:14px; }
    .trace-step { position:relative; border:1px solid var(--line); background:rgba(9,16,29,.24); border-radius:11px; padding:12px; min-height:140px; overflow-wrap:anywhere; }
    .trace-step::after { content:'→'; position:absolute; right:-10px; top:45%; color:var(--muted); font-weight:900; z-index:2; }
    .trace-step:last-child::after { content:''; }
    .trace-step.allowed { border-color:rgba(67,214,160,.4); }
    .trace-step.denied { border-color:rgba(255,113,133,.48); }
    .trace-step.warning { border-color:rgba(255,198,109,.4); }
    .trace-step-number { display:inline-grid; place-items:center; width:22px; height:22px; border-radius:7px; background:rgba(87,215,232,.12); color:var(--cyan); font-size:10px; font-weight:900; margin-bottom:9px; }
    .trace-step-title { font-size:11px; font-weight:850; margin-bottom:6px; }
    .trace-step-detail { color:var(--muted); font-size:10px; line-height:1.55; white-space:pre-wrap; }
    .trace-notes { margin-top:12px; padding:11px 12px; border-radius:10px; background:rgba(87,215,232,.045); border:1px solid rgba(87,215,232,.16); color:var(--muted); font-size:10px; white-space:pre-wrap; }
    body.light .request-explanation { background:linear-gradient(145deg,#fff,#f9fbff); }
    body.light .trace-step { background:rgba(247,249,252,.8); }
    @media (max-width:1100px) { .trace-flow { grid-template-columns:repeat(3,minmax(0,1fr)); } .trace-step:nth-child(3)::after { content:''; } }
    @media (max-width:760px) { .trace-flow { grid-template-columns:1fr; } .trace-step::after { content:'↓'; right:50%; top:auto; bottom:-13px; } .trace-step:nth-child(3)::after { content:'↓'; } }
    /* REQUEST_SPECIFIC_TAINT_TRACE_CSS_END */'''

PANEL = r'''        <!-- REQUEST_SPECIFIC_TAINT_TRACE_PANEL_BEGIN -->
        <div class="request-explanation section-gap" id="requestExplanation" aria-live="polite">
          <div class="request-explanation-head">
            <div><div class="request-explanation-title">Per-request taint → authorization flow</div><div class="request-explanation-subtitle">Shows the tracked ID source, object path, policy explanation, and actual response for the test you just ran.</div></div>
            <span class="trace-outcome warning" id="traceOutcome">WAITING FOR REQUEST</span>
          </div>
          <div class="request-explanation-subtitle" id="traceIntro">Run a direct, nested, or relationship test above to build an evidence-based explanation.</div>
          <div class="trace-flow" id="traceFlow"><div class="trace-step"><span class="trace-step-number">1</span><div class="trace-step-title">Request input</div><div class="trace-step-detail">Waiting for a test request.</div></div></div>
          <div class="trace-notes" id="traceNotes">The source tracker and policy replay will populate this area after a request. A tainted input is not automatically an attack.</div>
        </div>
        <!-- REQUEST_SPECIFIC_TAINT_TRACE_PANEL_END -->'''

JS = r'''// REQUEST_SPECIFIC_TAINT_TRACE_JS_BEGIN
      function traceStep(title, detail, state = '') {
        const node = document.createElement('div');
        node.className = 'trace-step' + (state ? ' ' + state : '');
        const number = document.createElement('span');
        number.className = 'trace-step-number';
        number.textContent = String($('traceFlow').children.length + 1);
        const heading = document.createElement('div');
        heading.className = 'trace-step-title';
        heading.textContent = title;
        const body = document.createElement('div');
        body.className = 'trace-step-detail';
        body.textContent = detail;
        node.append(number, heading, body);
        $('traceFlow').appendChild(node);
      }

      function findVisibleObjectIds(value, output = []) {
        if (!value || typeof value !== 'object' || output.length >= 50) return output;
        if (!Array.isArray(value) && value.id !== undefined && value.id !== null) {
          output.push({id:String(value.id), ownerId:value.ownerId ?? value.owner_id ?? null, name:value.name ?? null});
        }
        if (Array.isArray(value)) value.forEach(item => findVisibleObjectIds(item, output));
        else Object.values(value).forEach(item => findVisibleObjectIds(item, output));
        return output;
      }

      function renderTaintTrace({analysis, analysisError, query, variables, endpoint, httpStatus, response}) {
        const flow = $('traceFlow');
        flow.replaceChildren();
        const sources = analysis && Array.isArray(analysis.taint_sources) ? analysis.taint_sources : [];
        const objects = analysis && Array.isArray(analysis.objects) ? analysis.objects : [];
        const relationshipPaths = analysis && Array.isArray(analysis.relationship_paths) ? analysis.relationship_paths : [];
        const principal = analysis && analysis.principal ? analysis.principal : {};
        const visible = findVisibleObjectIds(response);
        const denied = objects.filter(item => item.authorization && item.authorization.decision === 'DENY');
        const allowed = objects.filter(item => item.authorization && item.authorization.decision === 'ALLOW');
        const visibleDenied = denied.filter(item => visible.some(obj => obj.id === String(item.object_id)));
        const gqlErrors = Boolean(response && typeof response === 'object' && Array.isArray(response.errors) && response.errors.length);
        let summary = 'ANALYSIS INCOMPLETE';
        let summaryClass = 'warning';
        let intro = 'This trace describes observed request evidence; it does not decide access by itself.';

        traceStep('1 · Authenticated principal', `User ID: ${principal.user_id ?? 'not available'}\nRole: ${principal.role ?? 'not available'}\nThe principal comes from the validated login token.`, '');

        if (sources.length) {
          const sourceLines = sources.slice(0, 5).map(source => {
            const variable = source.variable_name ? ` variable $${source.variable_name}` : '';
            return `${source.source_kind}${variable} = ${String(source.value)}\nArgument: ${source.field_name}.${source.argument_name}\nPath: ${source.graphql_path}`;
          });
          traceStep(`2 · Taint source tracked (${sources.length})`, sourceLines.join('\n\n'), '');
        } else {
          traceStep('2 · Taint source', 'The source tracker did not identify an ID-like input for this query. This is incomplete evidence, not proof that the request is safe.', 'warning');
        }

        if (objects.length) {
          const objectLines = objects.slice(0, 4).map(item => {
            const auth = item.authorization || {};
            return `${item.object_type} #${item.object_id}\nPath: ${item.graphql_path}\nOwner ID: ${item.owner_id ?? 'unknown'}\nPolicy: ${auth.decision ?? 'INCONCLUSIVE'}`;
          });
          traceStep(`3 · Object/path analysis (${objects.length})`, objectLines.join('\n\n'), objects.some(item => item.authorization && item.authorization.decision === 'INCONCLUSIVE') ? 'warning' : '');
          const policyLines = objects.slice(0, 4).map(item => {
            const auth = item.authorization || {};
            return `${item.graphql_path}: ${auth.reason ?? 'UNKNOWN'}\n${auth.explanation ?? 'No explanation supplied.'}`;
          });
          traceStep('4 · Authorization reasoning', policyLines.join('\n\n'), denied.length ? 'denied' : allowed.length === objects.length ? 'allowed' : 'warning');
        } else {
          traceStep('3 · Object/path analysis', 'No explicit object ID was extracted. This trace cannot make an object-level authorization claim.', 'warning');
          traceStep('4 · Authorization reasoning', 'No object policy decision is available for this query.', 'warning');
        }

        if (Number(httpStatus) === 403) {
          const detail = response && response.detail ? response.detail : {};
          const reason = detail.reason || (denied[0] && denied[0].authorization && denied[0].authorization.reason) || 'HTTP 403';
          summary = 'DENIED · HTTP 403'; summaryClass = 'denied';
          intro = `The request was rejected by the protected endpoint. Reason: ${reason}. The taint source shows which user-controlled ID/path was evaluated; the policy result explains why access was denied.`;
          traceStep('5 · Observed enforcement', `HTTP ${httpStatus}\nDecision: ${detail.decision || 'DENY'}\nReason: ${reason}\nRisk: ${detail.risk_level || 'see response details'} ${detail.risk_score !== undefined ? '(' + detail.risk_score + '/100)' : ''}`, 'denied');
        } else if (Number(httpStatus) >= 200 && Number(httpStatus) < 300 && !gqlErrors && endpoint.includes('graphql-insecure') && visibleDenied.length) {
          summary = 'POTENTIAL BOLA EXPOSURE'; summaryClass = 'denied';
          intro = 'The policy replay says this principal should not access the object, but the intentionally vulnerable endpoint returned an object with that ID.';
          traceStep('5 · Observed enforcement', `HTTP ${httpStatus}\nWARNING: unauthorized target ID(s) visible in response: ${visibleDenied.map(item => '#' + item.object_id).join(', ')}\nThis is a confirmed exposure in this test response.`, 'denied');
        } else if (Number(httpStatus) >= 200 && Number(httpStatus) < 300 && !gqlErrors && objects.length && denied.length && !visibleDenied.length) {
          summary = 'TARGET NOT OBSERVED'; summaryClass = 'warning';
          intro = 'The policy replay says at least one object should be denied, but the returned response did not visibly contain its ID. This may be field-level filtering; do not treat HTTP 200 alone as proof of access.';
          traceStep('5 · Observed enforcement', `HTTP ${httpStatus}\nTarget IDs not found in the response body.\nCheck resolver filtering and the raw GraphQL response before concluding that data was protected.`, 'warning');
        } else if (Number(httpStatus) >= 200 && Number(httpStatus) < 300 && !gqlErrors && objects.length && allowed.length === objects.length) {
          summary = 'ACCEPTED · POLICY ALLOWS'; summaryClass = 'allowed';
          intro = 'The request was accepted and the policy replay allowed every extracted object. The explanation below identifies the configured reason, such as OWNER_MATCH or ADMIN_OVERRIDE.';
          traceStep('5 · Observed enforcement', `HTTP ${httpStatus}\nGraphQL errors: none reported\nPolicy reason: ${allowed.map(item => item.authorization.reason).filter(Boolean).join(', ') || 'ALLOW'}`, 'allowed');
        } else if (gqlErrors) {
          summary = `GRAPHQL ERROR · HTTP ${httpStatus}`; summaryClass = 'warning';
          intro = 'The HTTP request completed, but GraphQL returned errors. This is not automatically an accepted or denied authorization result.';
          traceStep('5 · Observed response', `HTTP ${httpStatus}\nGraphQL errors: ${response.errors.length}\nInspect the actual error messages and policy decisions.`, 'warning');
        } else {
          summary = `HTTP ${httpStatus} · REVIEW`; summaryClass = 'warning';
          traceStep('5 · Observed response', `HTTP ${httpStatus}\nNo conclusive allow/deny explanation can be inferred from the available evidence.`, 'warning');
        }

        if (relationshipPaths.length) {
          const returnedChildren = visible.filter(item => item.ownerId !== null && item.ownerId !== undefined);
          const relationshipSummary = relationshipPaths.join(', ');
          $('traceNotes').textContent = `Nested selection paths in query: ${relationshipSummary}. ` +
            (returnedChildren.length ? `Objects visible in response with owner fields: ${returnedChildren.slice(0, 10).map(item => `#${item.id} (owner ${item.ownerId})`).join(', ')}. ` : '') +
            'The source tracker identifies the parent ID source; this report does not claim to enumerate hidden children unless the resolver/analysis explicitly reports them. ' +
            (analysis && analysis.notes ? analysis.notes.join(' ') : '');
        } else {
          $('traceNotes').textContent = (analysis && analysis.notes ? analysis.notes.join(' ') : 'No additional analysis notes available.') +
            (analysisError ? ` Explanation API unavailable: ${analysisError}` : '');
        }
        $('traceOutcome').textContent = summary;
        $('traceOutcome').className = 'trace-outcome ' + summaryClass;
        $('traceIntro').textContent = intro;
      }

      function resetTaintTrace() {
        $('traceOutcome').textContent = 'WAITING FOR REQUEST';
        $('traceOutcome').className = 'trace-outcome warning';
        $('traceIntro').textContent = 'Run a direct, nested, or relationship test above to build an evidence-based explanation.';
        $('traceFlow').replaceChildren();
        traceStep('Request input', 'Waiting for a test request.');
        $('traceNotes').textContent = 'Taint source data and policy replay will populate this area after a request. A tainted input is not automatically an attack.';
      }
      // REQUEST_SPECIFIC_TAINT_TRACE_JS_END'''

BUILD_REQUEST = r'''      function buildSelectedRequest() {
        const scenario = $('testScenario').value;
        if (scenario === 'direct') {
          const resourceId = positiveInteger('testResourceId', 'Resource ID');
          return {
            query: 'query DashboardDirectResource($resourceId: Int!) { resource(id: $resourceId) { id name ownerId objectType parentId } }',
            variables: { resourceId }
          };
        }
        if (scenario === 'nested') {
          const userId = positiveInteger('testUserId', 'User ID');
          const resourceId = positiveInteger('testResourceId', 'Resource ID');
          return {
            query: 'query DashboardNestedResource($userId: Int!, $resourceId: Int!) { user(id: $userId) { id username role resource(id: $resourceId) { id name ownerId objectType parentId } } }',
            variables: { userId, resourceId }
          };
        }
        const parentId = positiveInteger('testParentId', 'Parent/folder ID');
        return {
          query: 'query DashboardImplicitRelationship($parentId: Int!) { resource(id: $parentId) { id name ownerId children { id name ownerId parentId } } }',
          variables: { parentId }
        };
      }

'''

README = r'''# Per-request Taint & Authorization Flow Patch

This patch replaces the static-only explanation with a request-specific flow. After each dashboard test it displays:

1. The authenticated principal and role from the validated JWT.
2. Actual ID taint sources returned by `app.security.taint_sources.track_sources()`.
3. Parsed GraphQL object paths and ownership lookups.
4. A read-only re-evaluation by the project's existing `PolicyEngine`.
5. The actual HTTP / GraphQL outcome, distinguished from the policy replay.

For successful requests, the flow explains `OWNER_MATCH` or `ADMIN_OVERRIDE` from the configured engine. For HTTP 403, it shows the observed denial reason and risk data. For the intentionally vulnerable baseline, it warns if the same policy replay says DENY and the response visibly contains the target ID.

Relationship queries additionally show parsed nested selection paths and owner fields visible in the response. The tool does NOT invent hidden child IDs or claim that all internal propagation edges were dynamically observed. The API explicitly labels its policy check as a read-only replay, not the enforcement event itself.

## Install

1. Keep the app running or stop it; either is fine for file editing.
2. Extract this ZIP into the project root so `apply_taint_trace_dashboard.py` and `payload/` sit beside `app/` and `tests/`.
3. From a PowerShell terminal in the project root, run:

   ```powershell
   python .\apply_taint_trace_dashboard.py
   ```

4. Run `python -m pytest -q`.
5. Restart FastAPI if needed and hard-refresh `/dashboard` with Ctrl+F5.
6. Run one protected request for another user's object, then an owned-object request. Verify the flow shows `DENIED · HTTP 403` and `ACCEPTED · POLICY ALLOWS` respectively.

The installer backs up `app/main.py` and `app/static/dashboard.html` to `backups/taint_request_trace_before_patch_<timestamp>/` before writing. It is idempotent and stops if the expected source anchors are absent.

## Security notes / scope

- `/api/v1/taint-explain` requires the same JWT auth dependency as protected application routes.
- The endpoint does not execute the GraphQL request and does not change authorization decisions. It exposes analysis evidence to the authenticated dashboard session.
- Keep dashboard/test-console endpoints local-only for this research prototype and restrict them before deployment.
- This view uses the actual source tracker + object extractor + ownership lookup + current policy engine. It is not a whole-program taint engine or formal proof. If the source tracker returns no source, the UI states that the source was not found rather than assuming the request is safe.
'''


def main() -> None:
    if not MAIN.is_file() or not DASHBOARD.is_file():
        raise SystemExit("ERROR: Run from the GraphQL-Shield project root containing app/main.py and app/static/dashboard.html.")
    if not (ROOT / "app" / "security" / "taint_sources.py").is_file():
        raise SystemExit("ERROR: app/security/taint_sources.py was not found. No files changed.")
    if not TEST_SOURCE.is_file():
        raise SystemExit("ERROR: Regression test file is missing from the patch. No files changed.")
    module_text = SOURCE_MODULE.read_text(encoding="utf-8")
    test_text = TEST_SOURCE.read_text(encoding="utf-8")
    main_text = MAIN.read_text(encoding="utf-8-sig")
    html_text = DASHBOARD.read_text(encoding="utf-8-sig")

    # Build all modifications in memory and validate all anchors before backups/writes.
    if ROUTER_IMPORT not in main_text:
        import_anchor = "from app.core.dependencies import get_current_user"
        if import_anchor not in main_text:
            raise SystemExit("ERROR: Could not find the current_user import in app/main.py. No files changed.")
        main_text = main_text.replace(import_anchor, import_anchor + "\n" + ROUTER_IMPORT, 1)
    if ROUTER_INCLUDE not in main_text:
        health_anchor = '@app.get("/health")'
        if health_anchor not in main_text:
            raise SystemExit('ERROR: Could not find @app.get("/health") in app/main.py. No files changed.')
        main_text = main_text.replace(health_anchor, ROUTER_INCLUDE + "\n\n" + health_anchor, 1)

    if CSS_MARKER not in html_text:
        if "</style>" not in html_text:
            raise SystemExit("ERROR: CSS closing tag not found in dashboard.html. No files changed.")
        html_text = html_text.replace("</style>", CSS + "\n  </style>", 1)

    if HTML_MARKER not in html_text:
        result_line = re.search(r'(?m)^(\s*)<div class="console-result" aria-live="polite">.*$', html_text)
        if not result_line:
            raise SystemExit("ERROR: Test result panel not found in dashboard.html. No files changed.")
        indent = result_line.group(1)
        panel = PANEL.replace("        ", indent)
        insert_at = result_line.end()
        html_text = html_text[:insert_at] + "\n" + panel.rstrip() + html_text[insert_at:]

    if "function buildSelectedRequest()" not in html_text:
        if "      function buildSelectedQuery() {" not in html_text:
            raise SystemExit("ERROR: buildSelectedQuery() not found; dashboard source is different. No files changed.")
        start = html_text.index("      function buildSelectedQuery() {")
        end = html_text.index("      async function runSelectedTest() {", start)
        html_text = html_text[:start] + BUILD_REQUEST + html_text[end:]

    if JS_MARKER not in html_text:
        run_anchor = "      async function runSelectedTest() {"
        if run_anchor not in html_text:
            raise SystemExit("ERROR: runSelectedTest() not found. No files changed.")
        html_text = html_text.replace(run_anchor, JS + "\n\n" + run_anchor, 1)

    old_build = "        let query;\n        try { query = buildSelectedQuery(); }\n        catch (error) { showToast(error.message); return; }"
    new_build = "        let query;\n        let variables;\n        try { const requestSpec = buildSelectedRequest(); query = requestSpec.query; variables = requestSpec.variables; }\n        catch (error) { showToast(error.message); return; }"
    if old_build in html_text:
        html_text = html_text.replace(old_build, new_build, 1)
    elif "requestSpec = buildSelectedRequest()" not in html_text:
        raise SystemExit("ERROR: Could not update selected request builder. No files changed.")

    # Submit variables to both GraphQL and the source tracker.
    if "body: JSON.stringify({query}), cache:'no-store'" in html_text:
        html_text = html_text.replace("body: JSON.stringify({query}), cache:'no-store'", "body: JSON.stringify({query, variables}), cache:'no-store'", 1)
    elif "body: JSON.stringify({query, variables}), cache:'no-store'" not in html_text:
        raise SystemExit("ERROR: Could not find GraphQL request body in dashboard.js. No files changed.")

    old_output = "$('testResultBody').textContent = JSON.stringify({endpoint:$('testEndpoint').value, scenario:$('testScenario').value, query, http_status:graphqlResponse.status, response:parsedBody}, null, 2);\n          $('testPassword').value = '';"
    new_output = r'''$('testResultBody').textContent = JSON.stringify({endpoint:$('testEndpoint').value, scenario:$('testScenario').value, query, variables, http_status:graphqlResponse.status, response:parsedBody}, null, 2);
          let analysis = null;
          let analysisError = '';
          try {
            const explainResponse = await fetch('/api/v1/taint-explain', {
              method: 'POST',
              headers: {'Content-Type':'application/json','Accept':'application/json','Authorization':`Bearer ${token}`},
              body: JSON.stringify({query, variables}), cache:'no-store'
            });
            const explainPayload = await explainResponse.json().catch(() => ({}));
            if (!explainResponse.ok) throw new Error(`Explanation API returned HTTP ${explainResponse.status}: ${JSON.stringify(explainPayload)}`);
            analysis = explainPayload;
          } catch (explainError) {
            analysisError = explainError && explainError.message ? explainError.message : String(explainError);
          }
          renderTaintTrace({analysis, analysisError, query, variables, endpoint:$('testEndpoint').value, httpStatus:graphqlResponse.status, response:parsedBody});
          $('testPassword').value = '';'''
    if old_output in html_text:
        html_text = html_text.replace(old_output, new_output, 1)
    elif "renderTaintTrace({analysis, analysisError" not in html_text:
        raise SystemExit("ERROR: Could not attach trace rendering to the observed result. No files changed.")

    # Reset the evidence view along with the result panel.
    clear_anchor = "          $('testResultBody').textContent = 'The selected request response will appear here.';"
    if clear_anchor in html_text and "          resetTaintTrace();" not in html_text:
        html_text = html_text.replace(clear_anchor, clear_anchor + "\n          resetTaintTrace();", 1)

    old_clarification = "This diagram explains the project pipeline. The charts above are computed from audit-log rows; they are not a live taint trace viewer. Showing per-request taint paths would require the analysis engine to expose or persist those findings through an API."
    new_clarification = "The per-request flow above uses the actual taint source tracker, parsed object paths, ownership lookup, the existing policy engine in read-only replay, and the observed HTTP/GraphQL response. It does not claim to be a whole-program taint trace or to reveal child objects the resolver deliberately omitted."
    html_text = html_text.replace(old_clarification, new_clarification)

    # Ensure new router file goes into the existing security package.
    security_dir = ROOT / "app" / "security"
    security_dir.mkdir(parents=True, exist_ok=True)
    target_module = security_dir / "taint_request_explainer.py"
    tests_dir = ROOT / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    target_test = tests_dir / "test_taint_request_explainer.py"
    backup_dir = ROOT / "backups" / f"taint_request_trace_before_patch_{datetime.now():%Y%m%d_%H%M%S}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(MAIN, backup_dir / "main.py")
    shutil.copy2(DASHBOARD, backup_dir / "dashboard.html")
    if target_module.exists():
        shutil.copy2(target_module, backup_dir / "taint_request_explainer.py")
    if target_test.exists():
        shutil.copy2(target_test, backup_dir / "test_taint_request_explainer.py")

    target_module.write_text(module_text, encoding="utf-8")
    target_test.write_text(test_text, encoding="utf-8")
    MAIN.write_text(main_text, encoding="utf-8")
    DASHBOARD.write_text(html_text, encoding="utf-8")
    print("Per-request taint and authorization flow installed.")
    print(f"Backups: {backup_dir}")
    print("New authenticated route: POST /api/v1/taint-explain")
    print("Flow explains source inputs, object/owner policy replay, and observed request outcome.")
    print("Added focused regression tests: tests/test_taint_request_explainer.py")
    print("Next: python -m pytest -q")


if __name__ == "__main__":
    main()
