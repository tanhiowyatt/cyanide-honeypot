import sys

from pydantic import ValidationError

sys.path.append("src")
from cyanide.core.config_schema import CyanideConfig


def test_config_validation():
    bad_config = {
        "ssh": {"port": 70000},
        "ml": {},
        "cleanup": {},
        "output": {},
        "logging": {"directory": "logs"},
    }

    try:
        CyanideConfig(**bad_config)
        print("FAIL: Out of range port (70000) allowed")
        assert False, "Out of range port (70000) allowed"
    except ValidationError:
        print("SUCCESS: Caught out of range port 70000")

    good_config = {
        "ssh": {"port": 2222},
        "ml": {},
        "cleanup": {},
        "output": {},
        "logging": {"directory": "logs"},
    }
    try:
        CyanideConfig(**good_config)
        print("SUCCESS: Valid port allowed")
    except ValidationError as e:
        print(f"FAIL: Valid port rejected: {e}")
        assert False, f"Valid port rejected: {e}"


if __name__ == "__main__":
    try:
        test_config_validation()
        sys.exit(0)
    except AssertionError:
        sys.exit(1)
