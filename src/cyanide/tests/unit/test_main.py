from unittest.mock import MagicMock, patch

import pytest

from cyanide.main import async_main, is_docker, main


def test_is_docker():
    with patch("os.path.exists", return_value=True):
        assert is_docker()
    with patch("os.path.exists", return_value=False), patch("os.environ.get", return_value=None):
        assert not is_docker()


def test_main_catch_interrupt():
    with (
        patch("cyanide.main.asyncio.run", side_effect=KeyboardInterrupt),
        patch("cyanide.main.async_main", new_callable=MagicMock, return_value=None),
    ):
        with pytest.raises(KeyboardInterrupt):
            main()


def test_main_catch_exception():
    with (
        patch("cyanide.main.asyncio.run", side_effect=Exception("Test Error")),
        patch("cyanide.main.async_main", new_callable=MagicMock, return_value=None),
    ):
        main()


@pytest.mark.asyncio
async def test_async_main():
    with (
        patch("cyanide.main.load_config", return_value={"hostname": "test"}),
        patch("cyanide.main.print_startup_banner"),
        patch("asyncio.get_running_loop"),
        patch("cyanide.main.is_docker", return_value=False),
        patch("cyanide.main.CyanideServer") as mock_server,
    ):

        from unittest.mock import AsyncMock

        mock_server.return_value.start = AsyncMock()
        await async_main()
