import json
import sqlite3
import time
from unittest.mock import MagicMock, patch

from cyanide.logger import CyanideLogger
from cyanide.output.base import OutputPlugin
from cyanide.output.sqlite import Plugin as SQLitePlugin


# 1. Mock Plugin for architecture testing
class MockPlugin(OutputPlugin):
    def __init__(self, config):
        super().__init__(config)
        self.recorded_events = []
        self.write_called = MagicMock()

    def write(self, event):
        self.recorded_events.append(event)
        self.write_called(event)


def test_base_plugin_async_behavior():
    """Verify that OutputPlugin processes events asynchronously in a background thread."""
    plugin = MockPlugin({"enabled": True})
    plugin.start()

    test_event = {"test": "data"}
    plugin.emit(test_event)

    # Wait for the background thread to pick it up
    timeout = 2.0
    start = time.time()
    while not plugin.recorded_events and time.time() - start < timeout:
        time.sleep(0.1)

    assert len(plugin.recorded_events) == 1
    assert plugin.recorded_events[0] == test_event
    plugin.stop()


def test_logger_plugin_broadcast(tmp_path):
    """Verify CyanideLogger correctly loads and broadcasts to plugins."""
    log_dir = tmp_path / "logs"

    # We patch import_module to return our mock plugin class
    with patch("importlib.import_module") as mock_import:
        mock_module = MagicMock()
        # Create a "Plugin" class in our mock module
        mock_module.Plugin = MockPlugin
        mock_import.return_value = mock_module

        output_config = {"mock_plugin": {"enabled": True, "some_setting": "val"}}

        # Updated signature: config dict containing output and logging
        logger = CyanideLogger({"logging": {"directory": str(log_dir)}, "output": output_config})

        assert len(logger.plugins) == 1
        assert isinstance(logger.plugins[0], MockPlugin)

        # Log an event
        logger.log_event("session_123", "command.input", {"input": "whoami"})

        # Wait for async processing
        time.sleep(0.5)

        # Verify the plugin received the event
        plugin = logger.plugins[0]
        assert len(plugin.recorded_events) == 1
        assert plugin.recorded_events[0]["session"] == "session_123"
        assert plugin.recorded_events[0]["eventid"] == "command.input"
        assert plugin.recorded_events[0]["input"] == "whoami"

        for p in logger.plugins:
            p.stop()


def test_sqlite_plugin_real_write(tmp_path):
    """Verify the real SQLite plugin writes to disk correctly."""
    db_file = tmp_path / "test_events.sqlite"
    config = {"enabled": True, "path": str(db_file), "table": "test_events"}

    plugin = SQLitePlugin(config)
    plugin.start()

    event = {
        "timestamp": "2023-01-01T00:00:00Z",
        "session": "s1",
        "eventid": "login",
        "user": "root",
    }

    plugin.emit(event)

    # Wait for write
    time.sleep(1.0)
    plugin.stop()

    # Verify DB content
    assert db_file.exists()
    conn = sqlite3.connect(str(db_file))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM test_events")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 1
    # Check structure: (id, timestamp, session, eventid, data)
    assert rows[0][1] == "2023-01-01T00:00:00Z"
    assert rows[0][2] == "s1"
    assert rows[0][3] == "login"
    data = json.loads(rows[0][4])
    assert data["user"] == "root"


def test_plugin_resiliency_on_failure(tmp_path):
    """Verify that a failing plugin does not crash the logger."""
    log_dir = tmp_path / "logs"

    class FailingPlugin(OutputPlugin):
        def write(self, event):
            raise RuntimeError("Database is down!")

    with patch("importlib.import_module") as mock_import:
        mock_module = MagicMock()
        mock_module.Plugin = FailingPlugin
        mock_import.return_value = mock_module

        # Updated signature
        logger = CyanideLogger(
            {"logging": {"directory": str(log_dir)}, "output": {"failer": {"enabled": True}}}
        )

        # This shouldn't raise even though the plugin's background thread will fail
        logger.log_event("s", "e", "d")

        time.sleep(0.5)
        # Verify logger is still alive and we can log again
        logger.log_event("s2", "e2", "d2")

        for p in logger.plugins:
            p.stop()


def test_individual_plugin_instantiation_safety():
    """
    Verify that individual plugins can be instantiated even if dependencies are missing,
    as long as they are mocked correctly for the test environment.
    """
    # Test that MySQL plugin can be instantiated if we fake mysql-connector
    with patch.dict("sys.modules", {"mysql": MagicMock(), "mysql.connector": MagicMock()}):
        from cyanide.output.mysql import Plugin as MySQLPlugin

        config = {"enabled": True, "host": "127.0.0.1"}
        plugin = MySQLPlugin(config)
        assert plugin.host == "127.0.0.1"


def test_splunk_plugin_payload_format():
    """Verify Splunk plugin correctly formats its HEC payload."""
    with patch("requests.post") as mock_post:
        # Provide a successful mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        from cyanide.output.splunk_hec import Plugin as SplunkPlugin

        config = {"enabled": True, "url": "http://splunk", "token": "abc"}
        plugin = SplunkPlugin(config)

        event = {"timestamp": "2023", "session": "s1", "eventid": "ev"}
        plugin.write(event)

        args, kwargs = mock_post.call_args
        assert kwargs["json"]["event"] == event
        assert kwargs["headers"]["Authorization"] == "Splunk abc"
