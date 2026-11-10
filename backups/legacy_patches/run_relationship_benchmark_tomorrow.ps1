$ErrorActionPreference = "Stop"

Set-Location "C:\Users\CHINMAYANAND\Downloads\GraphQL-Shield"

python scripts/repeat_research_benchmarks.py `
    --count 5000 `
    --repeats 3 `
    --seed 20261011 `
    --output-root results/repeated_benchmark_after_relationship_detection_5000x3_tomorrow

if ($LASTEXITCODE -ne 0) {
    throw "Benchmark failed. Check the output above."
}
