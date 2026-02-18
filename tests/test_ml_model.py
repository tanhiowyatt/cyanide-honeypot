import pytest
import torch
import os
from cyanide.ml.model import CommandAutoencoder

# Skip if torch not available (though it should be)
pytest.importorskip("torch")

def test_model_init():
    """Test model initialization and dimensions."""
    model = CommandAutoencoder(input_dim=128, latent_dim=32)
    assert model.input_dim == 128
    assert model.latent_dim == 32
    assert isinstance(model.encoder, torch.nn.Sequential)
    assert isinstance(model.decoder, torch.nn.Sequential)

def test_preprocess():
    """Test command tokenization and normalization."""
    model = CommandAutoencoder(input_dim=50)
    cmd = "sudo ls -la"
    tensor = model.preprocess(cmd)
    
    # Check shape: [1, input_dim]
    assert tensor.shape == (1, 50)
    # Check values are normalized [0, 1]
    assert torch.all(tensor >= 0.0)
    assert torch.all(tensor <= 1.0)
    
    # Padding check
    # "sudo ls -la" is 11 chars. Rest should be 0.
    # We can check simple properties if tokenizer behaves standardly.

def test_prediction_basics():
    """Test forward pass and anomaly scoring."""
    model = CommandAutoencoder(input_dim=50)
    cmd = "ping google.com"
    is_anomaly, score, error = model.predict(cmd)
    
    assert isinstance(is_anomaly, (bool, torch.Tensor)) # usually tensor or bool
    assert 0.0 <= score <= 1.0
    assert error >= 0.0

def test_save_load(tmp_path):
    """Test model persistence."""
    model = CommandAutoencoder(input_dim=64, latent_dim=16)
    model.threshold = 0.123
    
    save_path = tmp_path / "model.pkl"
    model.save(save_path)
    
    assert save_path.exists()
    
    loaded_model = CommandAutoencoder.load(save_path)
    assert loaded_model.input_dim == 64
    assert loaded_model.latent_dim == 16
    assert abs(loaded_model.threshold - 0.123) < 1e-6
