import asyncio
from pathlib import Path
from typing import Any, Union

import aiofiles


class AsyncLogger:
    """
    Asynchronous logger to perform file I/O in a background task.
    Prevents blocking the main event loop during high-volume logging (e.g., TTY recording).
    """

    def __init__(self):
        self.queue: "asyncio.Queue[Any]" = asyncio.Queue()
        self._stop_event = asyncio.Event()
        self._worker_task = None

    async def start(self):
        """Start the background worker."""
        if self._worker_task is None:
            self._worker_task = asyncio.create_task(self._worker())

    async def stop(self):
        """Stop the background worker and flush remaining logs."""
        self._stop_event.set()
        if self._worker_task:
            await self.queue.join()  # Wait for queue to empty
            await self._worker_task

    def log(self, filepath: Path, content: Union[str, bytes], mode: str = "a"):
        """Schedule a log write."""
        self.queue.put_nowait((filepath, content, mode))

    async def _worker(self):
        """Background task to process log queue."""
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                # If stopped, don't wait indefinitely, just poll queue
                if self._stop_event.is_set():
                    try:
                        filepath, content, mode = self.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                else:
                    item = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                    filepath, content, mode = item

                try:
                    async with aiofiles.open(filepath, mode) as f:
                        await f.write(content)
                except Exception as e:
                    print(f"AsyncLogger Error writing to {filepath}: {e}")
                finally:
                    self.queue.task_done()

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                print(f"AsyncLogger Worker Error: {e}")
