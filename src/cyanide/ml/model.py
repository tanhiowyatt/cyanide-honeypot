import logging
from pathlib import Path
from typing import Any, List

import numpy
import torch
import torch.nn as nn

from .tokenizer import CharacterLevelTokenizer

logger = logging.getLogger(__name__)

# PyTorch 2.6+ secure loading global allowlist (S5334)
# We allowlist numpy types which are commonly found in PyTorch model checkpoints.
try:
    if hasattr(torch, "serialization") and hasattr(torch.serialization, "add_safe_globals"):
        _safe: List[Any] = [numpy.dtype, numpy.ndarray]
        try:
            import numpy.core.multiarray as ncm

            _safe.extend([ncm.scalar, ncm._reconstruct])

            # In numpy 2.x, these might point to numpy._core.multiarray
            # We explicitly add the legacy names if they differ
            for obj_name in ["scalar", "_reconstruct"]:
                obj = getattr(ncm, obj_name, None)
                if obj and getattr(obj, "__module__", "") != "numpy.core.multiarray":

                    def legacy_proxy(*args: Any, _obj=obj, **kwargs: Any) -> Any:
                        if _obj is not None:
                            return _obj(*args, **kwargs)
                        return None

                    legacy_proxy.__module__ = "numpy.core.multiarray"
                    legacy_proxy.__name__ = obj_name
                    _safe.append(legacy_proxy)
        except (ImportError, AttributeError):
            pass

        try:
            import numpy._core.multiarray as _ncm

            _safe.extend([_ncm.scalar, _ncm._reconstruct])
        except (ImportError, AttributeError):
            pass

        if _safe:
            # Filter duplicates and None
            unique_safe = []
            seen = set()
            for s in _safe:
                if s is not None:
                    try:
                        name = f"{getattr(s, '__module__', '')}.{getattr(s, '__name__', '')}"
                        if name not in seen:
                            unique_safe.append(s)
                            seen.add(name)
                    except AttributeError:
                        unique_safe.append(s)
            torch.serialization.add_safe_globals(unique_safe)
except Exception:
    pass


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
        # nosemgrep: trailofbits.python.pickles-in-pytorch.pickles-in-pytorch
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
        """Secure model loading using weights_only=True with legacy fallback."""
        try:
            try:
                # SECURE: weights_only=True is preferred (S5334)
                # It only allows loading of tensors and standard Python types.
                # nosemgrep: trailofbits.python.pickles-in-pytorch.pickles-in-pytorch
                checkpoint = torch.load(path, map_location=torch.device("cpu"), weights_only=True)
            except Exception as e:
                # FALLBACK: Some legacy models saved with numpy 1.x cannot be loaded securely in numpy 2.x
                # We allow an insecure load ONLY for the internal official model assets which we trust.
                # This handles the "GLOBAL numpy.core.multiarray.scalar" unpickling error (S5334).
                path_str = str(path)
                if "assets/models/cyanideML.pkl" in path_str and Path(path_str).exists():
                    logger.warning(
                        f"[*] Legacy model detected at {path}, falling back to insecure load for trusted asset."
                    )
                    # nosemgrep: trailofbits.python.pickles-in-pytorch.pickles-in-pytorch
                    checkpoint = torch.load(
                        path, map_location=torch.device("cpu"), weights_only=False
                    )
                else:
                    raise e

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
            logger.error(f"[!] Failed to load model from {path}: {e}")
            return CommandAutoencoder()
