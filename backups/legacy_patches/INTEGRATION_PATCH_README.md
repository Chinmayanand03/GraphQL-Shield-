# GraphQL Shield Research Hardening Integration Patch

This patch connects the research-hardening helpers already present in the project to the benchmark runner. It overlays files at the project root; it does not replace the gateway, policy engine, attack generator, or existing `integrated_verification.py` module.

## Files in this patch

**Replaces existing files**
- `app/benchmarks/runner.py`
- `app/benchmarks/dataset.py`
- `app/benchmarks/evaluator.py`
- `app/security/dynamic_verifier.py`

**Adds new files**
- `app/benchmarks/research_hardening_integration.py`
- `tests/test_research_hardening_integration.py`

The project must already contain the helpers added earlier:
- `app/benchmarks/ground_truth.py`
- `app/benchmarks/attack_variants.py`
- `app/security/relationship_extractor.py`

## What changes

1. Benchmark labels are recomputed by `label_case_with_oracle` from the object catalog and ownership/path metadata. The prior `is_bola`, `expected_authorized`, scenario name, and detector predictions are not used as oracle decision inputs.
2. The dataset adds `relationship_legitimate` and `relationship_bola` cases. These query `resource.children` without an explicit child ID, testing access to children beneath an authorized parent.
3. The runner creates the foreign-owned child link (`object 102` below folder `201`) only in its temporary evaluation database. It does not modify the configured development database or `app/seed.py`.
4. Analyzer findings are enriched with their query, variables, principal, target, and response path, then passed to `generate_variants_from_findings` and adapted to the existing `AttackCase` type.
5. Implicit relationship paths are parsed, child records are resolved through the catalog, and each child is replayed against `/graphql-insecure` and `/graphql` through the existing dynamic verifier.
6. The replay report and raw rows are written to `research_hardening_verification.json` and `research_hardening_verification_raw.csv` under the benchmark output directory.
7. A collection response containing other children but not the target is classified as `NOT_EXPOSED`, not as a possible exposure. HTTP 401/403 blocking and target absence are reported separately.

General analyzer-derived variant replay is capped at 64 variants by default. Each generated variant is tested against both endpoints. Unique implicit relationship child probes are retained separately from that cap.

## Apply the patch

From the project root in PowerShell, back up the four replaced files, then extract this ZIP into the project root:

```powershell
$backup = "backups/research_hardening_pre_integration"
New-Item -ItemType Directory -Force $backup | Out-Null
Copy-Item app/benchmarks/runner.py "$backup/runner.py"
Copy-Item app/benchmarks/dataset.py "$backup/dataset.py"
Copy-Item app/benchmarks/evaluator.py "$backup/evaluator.py"
Copy-Item app/security/dynamic_verifier.py "$backup/dynamic_verifier.py"
Expand-Archive -Path .\research_integration_patch.zip -DestinationPath . -Force
```

Run the full suite:

```powershell
python -m pytest -q
```

Then run a small end-to-end benchmark first:

```powershell
python scripts/run_research_benchmark.py --count 100 --seed 20261011 --output-dir results/research_hardening_smoke
```

Confirm the report contains `research_hardening_verification`, and that the output directory has `research_hardening_verification.json` and `research_hardening_verification_raw.csv`.

## Validation status

The updated modules passed Python syntax compilation. The benchmark tests plus both hardening test modules passed **31 tests in a stripped validation harness**. The complete application test suite was not run here because this execution environment does not include the project's full application dependencies/source tree. Run the commands above in the actual repository before treating the integration as validated.
