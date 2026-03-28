from typing import Any, Dict
from unittest.mock import patch

import pytest

from cyanide.output.dshield import Plugin


@pytest.fixture
def dshield_plugin():
    config: Dict[str, Any] = {"userid": "user1", "authkey": "key1", "batch_size": 2}
    return Plugin(config)


def test_dshield_init(dshield_plugin):
    assert dshield_plugin.userid == "user1"
    assert dshield_plugin.authkey == "key1"
    assert dshield_plugin.batch_size == 2


@patch("requests.post")
def test_dshield_write_and_flush(mock_post, dshield_plugin):
    mock_post.return_value.status_code = 200

    event1 = {
        "eventid": "auth",
        "timestamp": "2023-01-01T00:00:00",
        "data": {"client_ip": "1.1.1.1", "client_port": "1234", "dst_port": 22},
        "server_ip": "2.2.2.2",
    }

    # Write first event - should be buffered
    dshield_plugin.write(event1)
    assert len(dshield_plugin.buffer) == 1
    assert mock_post.called is False

    # Write second event - should trigger flush
    dshield_plugin.write(event1)
    assert len(dshield_plugin.buffer) == 0
    assert mock_post.called is True
    assert "X-Dshield-AuthID" in mock_post.call_args[1]["headers"]


def test_dshield_no_auth():
    config: Dict[str, Any] = {}
    plugin = Plugin(config)
    plugin.write({"eventid": "auth"})
    assert len(plugin.buffer) == 0


def test_dshield_ignore_event(dshield_plugin):
    dshield_plugin.write({"eventid": "other"})
    assert len(dshield_plugin.buffer) == 0
