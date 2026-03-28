import asyncio
from pathlib import Path
from typing import Any, Optional, Union, cast

import aiofiles


class AsyncLogger:
    """
    Asynchronous logger to perform file I/O in a background task.
    Prevents blocking the main event loop during high-volume logging (e.g., TTY recording).
    """

    # Function 9: Initializes the class instance and its attributes.
    def __init__(self):
        self.queue: "asyncio.Queue[Any]" = asyncio.Queue()
        self._stop_event = asyncio.Event()
        self._worker_task = None

    # Function 10: Performs operations related to start.
    def start(self):
        """Start the background worker."""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker())

    # Function 11: Performs operations related to stop.
    async def stop(self):
        """Stop the background worker and flush remaining logs."""
        self._stop_event.set()
        if self._worker_task:
            try:
                # Give it a few seconds to flush remaining logs
                await asyncio.wait_for(self.queue.join(), timeout=3.0)
            except asyncio.TimeoutError:
                pass

            # Cancel the worker if it's still running
            if not self._worker_task.done():
                self._worker_task.cancel()
                await self._worker_task

    # Function 12: Handles event logging and telemetry.
    def log(self, filepath: Path, content: Union[str, bytes], mode: str = "a"):
        """Schedule a log write."""
        self.queue.put_nowait((filepath, content, mode))

    async def _get_next_item(self) -> Optional[tuple[Path, Union[str, bytes], str]]:
        """Helper to get the next item from the queue with correct logic for drain vs wait."""
        if self._stop_event.is_set():
            try:
                item = self.queue.get_nowait()
                return cast(tuple[Path, Union[str, bytes], str], item)
            except asyncio.QueueEmpty:
                return None

        # Wait for an item, but don't block forever so we can check stop_event
        try:
            item = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            return cast(tuple[Path, Union[str, bytes], str], item)
        except Exception:
            return None

    async def _write_log_item(self, filepath: Path, content: Union[str, bytes], mode: str):
        """Helper to safely perform file I/O and mark task completion."""
        try:
            async with aiofiles.open(filepath, mode) as f:  # type: ignore[call-overload]
                await f.write(content)
        except Exception as e:
            import sys

            print(f"ERROR: AsyncLogger failed to write to {filepath}: {e}", file=sys.stderr)
        finally:
            self.queue.task_done()

    # Function 13: Performs operations related to worker.
    async def _worker(self):
        """Background task to process log queue."""
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                item = await self._get_next_item()
                if item is None:
                    if self._stop_event.is_set():
                        break
                    continue

                filepath, content, mode = item
                await self._write_log_item(filepath, content, mode)

            except asyncio.CancelledError:
                # Log to stderr since logging system might be closing
                import sys

                print("AsyncLogger worker cancelled, finishing queue...", file=sys.stderr)
                raise
            except Exception as e:
                import sys

                print(f"AsyncLogger worker error: {e}", file=sys.stderr)
                await asyncio.sleep(0.1)  # Prevent tight loop on persistent error
                continue
