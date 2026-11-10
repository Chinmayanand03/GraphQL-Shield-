import time
import json
import csv
import os
from fastapi.testclient import TestClient

from app.main import app
from app.seed import seed_database
from app.config import settings
from app.core.security import create_access_token

def run_evaluation():
    print("Initializing Phase 11 Evaluation...")
    
    # Use an isolated evaluation database
    settings.DATABASE_URL = "sqlite:///./eval_shield.db"
    seed_database()
    
    client = TestClient(app)
    
    # Using User 101 (Alice)
    token = create_access_token(user_id=101, role="user")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test Queries
    # Legitimate: Alice asks for her own resource
    legit_query = {"query": "{ resource(id: 101) { name } }"}
    # BOLA: Alice asks for Bob's resource
    bola_query = {"query": "{ resource(id: 102) { name } }"}
    
    ITERATIONS = 500
    
    results = {
        "insecure": {"legit_times": [], "bola_times": [], "blocked_bola": 0, "false_positives": 0},
        "secure": {"legit_times": [], "bola_times": [], "blocked_bola": 0, "false_positives": 0}
    }
    
    print(f"Running {ITERATIONS} queries against INSECURE endpoint...")
    for _ in range(ITERATIONS):
        # Legit
        start = time.perf_counter()
        res = client.post("/graphql-insecure", json=legit_query, headers=headers)
        duration = (time.perf_counter() - start) * 1000
        results["insecure"]["legit_times"].append(duration)
        if res.status_code == 403:
            results["insecure"]["false_positives"] += 1
            
        # BOLA
        start = time.perf_counter()
        res = client.post("/graphql-insecure", json=bola_query, headers=headers)
        duration = (time.perf_counter() - start) * 1000
        results["insecure"]["bola_times"].append(duration)
        if res.status_code == 403:
            results["insecure"]["blocked_bola"] += 1

    print(f"Running {ITERATIONS} queries against SECURE endpoint...")
    for _ in range(ITERATIONS):
        # Legit
        start = time.perf_counter()
        res = client.post("/graphql", json=legit_query, headers=headers)
        duration = (time.perf_counter() - start) * 1000
        results["secure"]["legit_times"].append(duration)
        if res.status_code == 403:
            results["secure"]["false_positives"] += 1
            
        # BOLA
        start = time.perf_counter()
        res = client.post("/graphql", json=bola_query, headers=headers)
        duration = (time.perf_counter() - start) * 1000
        results["secure"]["bola_times"].append(duration)
        if res.status_code == 403:
            results["secure"]["blocked_bola"] += 1
            
    # Computations
    def avg(lst): return sum(lst) / len(lst) if lst else 0
    
    avg_insec_legit = avg(results["insecure"]["legit_times"])
    avg_sec_legit = avg(results["secure"]["legit_times"])
    avg_insec_bola = avg(results["insecure"]["bola_times"])
    avg_sec_bola = avg(results["secure"]["bola_times"])
    
    authz_overhead = avg_sec_legit - avg_insec_legit
    
    det_rate = (results["secure"]["blocked_bola"] / ITERATIONS) * 100
    fp_rate = (results["secure"]["false_positives"] / ITERATIONS) * 100
    
    report = {
        "evaluation_parameters": {
            "iterations_per_type": ITERATIONS,
            "total_requests": ITERATIONS * 4
        },
        "performance_latency_ms": {
            "without_gateway_avg_ms": round(avg_insec_legit, 3),
            "with_gateway_avg_ms": round(avg_sec_legit, 3),
            "authorization_decision_overhead_ms": round(authz_overhead, 3)
        },
        "security_metrics": {
            "total_legitimate_requests": ITERATIONS,
            "total_bola_attempts": ITERATIONS,
            "insecure_endpoint": {
                "blocked_bola": results["insecure"]["blocked_bola"],
                "detection_rate_percent": (results["insecure"]["blocked_bola"] / ITERATIONS) * 100
            },
            "secure_gateway": {
                "blocked_bola": results["secure"]["blocked_bola"],
                "detection_rate_percent": round(det_rate, 2),
                "false_positives": results["secure"]["false_positives"],
                "false_positive_rate_percent": round(fp_rate, 2)
            }
        }
    }
    
    # Save to JSON
    with open("performance_evaluation.json", "w") as f:
        json.dump(report, f, indent=4)
        
    # Save raw dataset to CSV for graphs
    with open("performance_raw_data.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["iteration", "type", "endpoint", "latency_ms"])
        for i in range(ITERATIONS):
            writer.writerow([i+1, "legitimate", "insecure", results["insecure"]["legit_times"][i]])
            writer.writerow([i+1, "bola", "insecure", results["insecure"]["bola_times"][i]])
            writer.writerow([i+1, "legitimate", "secure", results["secure"]["legit_times"][i]])
            writer.writerow([i+1, "bola", "secure", results["secure"]["bola_times"][i]])

    print("\nEvaluation Complete! Results saved to performance_evaluation.json and performance_raw_data.csv")
    print(json.dumps(report, indent=4))
    
    # Cleanup DB
    if os.path.exists("eval_shield.db"):
        try:
            os.remove("eval_shield.db")
        except:
            pass

if __name__ == "__main__":
    # Create scripts folder if not exists
    os.makedirs("scripts", exist_ok=True)
    run_evaluation()
