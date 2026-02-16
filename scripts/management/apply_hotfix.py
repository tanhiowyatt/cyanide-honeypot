
import sys
import os
import torch
from pathlib import Path

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.getcwd(), 'src')))

from cyanide.ml.model import CommandAutoencoder
from cyanide.ml.classifier import KnowledgeBase

MODEL_DIR = Path("ai_models/cyanideML")
KB_DATA_DIR = Path("data/ml_training/kb_ready") 

def patch_autoencoder():
    print("[*] Patching Autoencoder...")
    model_path = MODEL_DIR / "cyanideML.pkl"
    try:
        # Load
        model = CommandAutoencoder.load(model_path)
        print(f"    - Current threshold: {model.threshold}")
        
        # Patch
        model.threshold = 0.0020
        print(f"    - New threshold: {model.threshold}")
        
        # Save
        model.save(model_path)
        print(f"    [+] Autoencoder matched and saved.")
    except Exception as e:
        print(f"    [!] Failed to patch Autoencoder: {e}")

def rebuild_kb():
    print("[*] Rebuilding Knowledge Base with new parameters...")
    kb_path = MODEL_DIR / "knowledge_base.pkl"
    try:
        # Instantiate NEW KB (uses new __init__ with improved TF-IDF)
        kb = KnowledgeBase()
        
        # Load Data
        if not KB_DATA_DIR.exists():
            print(f"    [!] KB Data directory not found: {KB_DATA_DIR}")
            return
            
        kb.load_data(KB_DATA_DIR)
        
        # Build Index
        kb.build_index()
        
        # Save
        kb.save(kb_path)
        print(f"    [+] Knowledge Base rebuilt and saved.")
        
    except Exception as e:
        print(f"    [!] Failed to rebuild KB: {e}")

if __name__ == "__main__":
    patch_autoencoder()
    rebuild_kb()
