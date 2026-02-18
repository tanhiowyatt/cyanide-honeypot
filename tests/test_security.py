import datetime
import os
import pickle

import pytest

from cyanide.core import security


def test_safe_loads_builtins():
    """Test loading safe builtin types."""
    data = {"a": 1, "b": [1, 2, 3], "c": "string", "d": {1, 2}}
    serialized = pickle.dumps(data)
    loaded = security.loads(serialized)
    assert loaded == data


def test_unsafe_loads_os_system():
    """Test that loading os.system raises UnpicklingError."""

    class Malicious:
        def __reduce__(self):
            return (os.system, ("echo hacked",))

    serialized = pickle.dumps(Malicious())

    with pytest.raises(pickle.UnpicklingError) as excinfo:
        security.loads(serialized)
    assert "Unsafe class" in str(excinfo.value)


def test_allowed_modules_datetime():
    """Test loading allowed modules like datetime."""
    data = datetime.datetime(2023, 1, 1, 12, 0, 0)
    serialized = pickle.dumps(data)
    loaded = security.loads(serialized)
    assert loaded == data


def test_disallowed_module():
    """Test that a non-whitelisted module is rejected."""
    # Using a standard library class not in the whitelist that is picklable
    import decimal

    data = decimal.Decimal("1.5")
    serialized = pickle.dumps(data)

    with pytest.raises(pickle.UnpicklingError) as excinfo:
        security.loads(serialized)
    assert "Unsafe class" in str(excinfo.value)
