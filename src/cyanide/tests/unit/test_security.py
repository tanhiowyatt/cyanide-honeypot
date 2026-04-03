import io
import pickle

import pytest

from cyanide.core.security import load, loads


def test_restricted_unpickler_safe():
    data = pickle.dumps({"a": 1, "b": [1, 2, 3]})
    unpickled = loads(data)
    assert unpickled["a"] == 1
    assert unpickled["b"] == [1, 2, 3]


def test_restricted_unpickler_unsafe():
    class Unsafe:
        def __reduce__(self):
            return (os.system, ("ls",))

    import os

    data = pickle.dumps(Unsafe())
    with pytest.raises(pickle.UnpicklingError):
        loads(data)


def test_restricted_unpickler_codecs():
    import _codecs

    data = pickle.dumps(_codecs.encode)
    unpickled = loads(data)
    assert unpickled == _codecs.encode


def test_secure_load():
    data = pickle.dumps([1, 2, 3])
    f = io.BytesIO(data)
    assert load(f) == [1, 2, 3]
