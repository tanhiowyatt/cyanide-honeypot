
#!/usr/bin/env python3
import argparse
import glob
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.append(
    str(Path(__file__).resolve().parent.parent.parent / "src")
)  # Adjusted path for new location
sys.path.append(str(Path.cwd() / "src"))

import numpy as np

# PyTorch imports for training loop
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset

from cyanide.core.config import load_config
from cyanide.ml.classifier import KnowledgeBase
from cyanide.ml.model import CommandAutoencoder


class CommandDataset(Dataset):
    def __init__(self, commands, tokenizer):
        self.commands = commands
        self.tokenizer = tokenizer

    def __len__(self):
        return len(self.commands)

    def __getitem__(self, idx):
        cmd = self.commands[idx]
        tokens = self.tokenizer.encode(cmd)
        # Normalize to [0, 1] for Autoencoder
        normalized = np.array(tokens, dtype=np.float32) / 128.0
        return torch.tensor(normalized, dtype=torch.float32)


def load_hacker_commands(path):
    """Load command strings from JSONL files."""
    commands = []
    # Search relative to project root or absolute paths
    # data/ml_training/hacker_methods is typical
    project_root = Path(__file__).resolve().parent.parent.parent
    if not Path(path).is_absolute():
        path = project_root / path

    files = glob.glob(str(Path(path) / "**" / "*.jsonl"), recursive=True)
    files.extend(glob.glob(str(Path(path) / "*.jsonl")))  # Add direct files

    print(f"[*] Loading hacker commands from {len(files)} files in {path}...")
    count = 0
    for fpath in files:
        try:
            with open(fpath, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        # Extract command
                        cmd = entry.get("command") or entry.get("cmd") or entry.get("input")
                        if cmd:
                            commands.append(str(cmd))
                            count += 1
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"[!] Error reading {fpath}: {e}")

    print(f"[*] Loaded {len(commands)} unique commands.")
    return list(set(commands))  # Remove duplicates


def train_anomaly_detector(force=False):
    """
    Train PyTorch Autoencoder.
    """
    config = load_config()
    ml_conf = config.get("ml", {})

    # Check scheduling
    state_file = Path("var/lib/cyanide/ml_state.json")
    if state_file.exists() and not force:
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
            last_run = state.get("last_train_run", 0)
            interval_days = ml_conf.get("retraining_interval_days", 7)
            if time.time() - last_run < interval_days * 24 * 3600:
                print(
                    f"[*] Skipping model training (less than {interval_days} days since last run). use --force to override."
                )
                return
        except Exception:
            pass

    hacker_methods_path = ml_conf.get("training_data", {}).get("hacker_methods")
    model_path = Path(ml_conf.get("model_path"))
    if not model_path.is_absolute():
        model_path = Path.cwd() / model_path

    print("\n--- Phase 1: Training Anomaly Detector (PyTorch) ---")

    # 1. Load Data
    commands = load_hacker_commands(hacker_methods_path)
    if not commands:
        print("[!] No training data found!")
        return

    # 2. Initialize Model
    model = CommandAutoencoder()
    model.train()

    # 3. Prepare DataLoader
    dataset = CommandDataset(commands, model.tokenizer)
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True, pin_memory=True)

    # 4. Optimizer & Scheduler
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, "min", patience=3, factor=0.5)
    criterion = nn.MSELoss()

    epochs = 20  # Increased epochs for better convergence

    print(f"[*] Starting training on {len(commands)} commands for {epochs} epochs...")

    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for batch in dataloader:
            batch = batch.to(model.device)

            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        avg_loss = total_loss / len(dataloader)

        # Step Scheduler
        scheduler.step(avg_loss)

        if (epoch + 1) % 5 == 0:
            print(f"    Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.6f}")

    # Calculate Threshold (95th percentile of reconstruction error on training data)
    print("[*] Calculating threshold...")
    model.eval()
    errors = []
    with torch.no_grad():
        for batch in dataloader:
            batch = batch.to(model.device)
            reconstructed = model(batch)
            batch_errors = torch.mean((batch - reconstructed) ** 2, dim=1)
            errors.extend(batch_errors.cpu().numpy())

    threshold = np.percentile(errors, 95)
    model.threshold = threshold
    print(f"[*] Threshold set to: {threshold:.6f}")

    # Save
    model.save(model_path)

    # Update State
    state_file.parent.mkdir(parents=True, exist_ok=True)
    with open(state_file, "w") as f:
        json.dump({"last_train_run": time.time()}, f)

    print("[+] Anomaly Detector Training Complete.")


def main():
    parser = argparse.ArgumentParser(description="Cyanide ML Training Manager")
    parser.add_argument("--train-model", action="store_true", help="Train anomaly detector")
    parser.add_argument("--force", action="store_true", help="Force training")

    args = parser.parse_args()

    if not args.train_model:
        # Default behavior: train model if run directly, or show help
        # But for consistency with previous usage:
        print("Usage: --train-model [--force]")
        sys.exit(1)

    if args.train_model:
        train_anomaly_detector(args.force)


if __name__ == "__main__":
    main()
