from pathlib import Path

import torch
import torch.nn as nn

from .tokenizer import CharacterLevelTokenizer


class CommandAutoencoder(nn.Module):
    """
    Autoencoder for detecting anomalous commands.
    Architecture: Input (512) -> Encoder -> Bottleneck (64) -> Decoder -> Output (512)
    """

    def __init__(self, input_dim=512, latent_dim=64):
        super(CommandAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.threshold = 0.0020  # Hotfix: Lowered significantly to catch more attacks

        self.tokenizer = CharacterLevelTokenizer(max_length=input_dim)

        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, latent_dim),
            nn.ReLU(),
        )

        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, input_dim),
            # Output should be in range [0, 1] if inputs are normalized
            # But here inputs are integer tokens... wait.
            # Tokenizer returns INTEGERS [0, vocab_size].
            # Autoencoder usually inputs Floats [0, 1].
            # We need an Embedding layer or normalize the tokens?
            # The spec says: "Normalized = (tokens - min) / (max - min)"
            # So input is Float [0, 1]. Sigmoid is correct.
            nn.Sigmoid(),
        )

        # Device management
        self.device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
        self.to(self.device)

    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    def preprocess(self, command):
        """Tokenize and normalize input command."""
        tokens = self.tokenizer.encode(command)
        # Normalize to [0, 1] based on vocab size (approx 100 chars)
        # Assuming ASCII ~128.
        vocab_size = 128.0
        normalized = [float(t) / vocab_size for t in tokens]
        tensor = torch.tensor([normalized], dtype=torch.float32).to(self.device)
        return tensor

    def get_reconstruction_error(self, x):
        """Calculate MSE reconstruction error."""
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error.item()

    def predict(self, command):
        """
        Returns (is_anomaly, score, confidence)
        """
        vector = self.preprocess(command)
        error = self.get_reconstruction_error(vector)

        is_anomaly = error > self.threshold
        # Score normalized roughly to [0, 1] relative to threshold?
        # Specification says: score = min(error / threshold, 1.0)
        if self.threshold > 0:
            score = min(error / self.threshold, 1.0) + (0.1 if is_anomaly else 0)
            score = min(score, 1.0)
        else:
            score = 1.0 if is_anomaly else 0.0

        pass

        return is_anomaly, score, error

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # nosemgrep: trailofbits.python.pickles-in-pytorch.pickles-in-pytorch
        torch.save(
            {
                "model_state": self.state_dict(),
                "threshold": self.threshold,
                "input_dim": self.input_dim,
                "latent_dim": self.latent_dim,
                "tokenizer": self.tokenizer,
            },
            path,
        )
        print(f"[*] Model saved to {path}")

    @staticmethod
    def load(path):
        try:
            # nosemgrep: trailofbits.python.pickles-in-pytorch.pickles-in-pytorch
            checkpoint = torch.load(
                path, map_location=torch.device("cpu"), weights_only=False
            )  # Map to CPU first

            model = CommandAutoencoder(
                input_dim=checkpoint.get("input_dim", 512),
                latent_dim=checkpoint.get("latent_dim", 64),
            )
            model.load_state_dict(checkpoint["model_state"])
            model.threshold = checkpoint.get("threshold", 0.05)
            # Restore tokenizer state if present
            if "tokenizer" in checkpoint:
                # Checkpoint might contain the object itself or its state
                # Here we saved the object (pickle), so it should be fine.
                # But safer to re-initialize if it was just state.
                # Given the save method dumps the object, we just assign it.
                model.tokenizer = checkpoint["tokenizer"]

            # Move to device
            model.to(model.device)
            model.eval()
            print(f"[*] PyTorch Autoencoder loaded from {path}")
            return model
        except Exception as e:
            print(f"[!] Failed to load model: {e}")
            return CommandAutoencoder()
