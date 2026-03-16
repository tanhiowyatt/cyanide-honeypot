import logging
from pathlib import Path

import torch
import torch.nn as nn

from .tokenizer import CharacterLevelTokenizer

logger = logging.getLogger(__name__)


class CommandAutoencoder(nn.Module):
    """
    Autoencoder for detecting anomalous commands.
    Architecture: Input (512) -> Encoder -> Bottleneck (64) -> Decoder -> Output (512)
    """

    # Function 125: Initializes the class instance and its attributes.
    def __init__(self, input_dim=512, latent_dim=64):
        super(CommandAutoencoder, self).__init__()

        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.threshold = 0.0020

        self.tokenizer = CharacterLevelTokenizer(max_length=input_dim)

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

        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 128),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(256, input_dim),
            nn.Sigmoid(),
        )

        self.device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
        self.to(self.device)

    # Function 126: Performs operations related to forward.
    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

    # Function 127: Performs operations related to preprocess.
    def preprocess(self, command):
        """Tokenize and normalize input command."""
        tokens = self.tokenizer.encode(command)
        vocab_size = 128.0
        normalized = [float(t) / vocab_size for t in tokens]
        tensor = torch.tensor([normalized], dtype=torch.float32).to(self.device)
        return tensor

    # Function 128: Retrieves reconstruction error data.
    def get_reconstruction_error(self, x):
        """Calculate MSE reconstruction error."""
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            error = torch.mean((x - reconstructed) ** 2, dim=1)
        return error.item()

    # Function 129: Performs operations related to predict.
    def predict(self, command):
        """
        Returns (is_anomaly, score, confidence)
        """
        vector = self.preprocess(command)
        error = self.get_reconstruction_error(vector)

        is_anomaly = error > self.threshold
        if self.threshold > 0:
            score = min(error / self.threshold, 1.0) + (0.1 if is_anomaly else 0)
            score = min(score, 1.0)
        else:
            score = 1.0 if is_anomaly else 0.0

        return is_anomaly, score, error

    # Function 130: Performs operations related to save.
    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "model_state": self.state_dict(),
                "threshold": float(self.threshold),
                "input_dim": int(self.input_dim),
                "latent_dim": int(self.latent_dim),
            },
            path,
        )
        logger.info(f"[*] Model saved to {path}")

    # Function 131: Performs operations related to load.
    @staticmethod
    def load(path):
        try:
            pass

            try:
                checkpoint = torch.load(path, map_location=torch.device("cpu"), weights_only=True)
            except Exception as e:
                error_msg = str(e)
                if "numpy.core.multiarray.scalar" in error_msg:
                    checkpoint = torch.load(
                        path, map_location=torch.device("cpu"), weights_only=False
                    )
                else:
                    logger.warning(
                        f"[*] Secure load failed for {path} ({e}), retrying with weights_only=False"
                    )
                    checkpoint = torch.load(
                        path, map_location=torch.device("cpu"), weights_only=False
                    )

            model = CommandAutoencoder(
                input_dim=checkpoint.get("input_dim", 512),
                latent_dim=checkpoint.get("latent_dim", 64),
            )
            model.load_state_dict(checkpoint["model_state"])
            model.threshold = checkpoint.get("threshold", 0.05)

            model.to(model.device)
            model.eval()
            logger.info(f"[*] PyTorch Autoencoder loaded from {path}")
            return model
        except Exception as e:
            logger.error(f"[!] Failed to load model: {e}")
            return CommandAutoencoder()
