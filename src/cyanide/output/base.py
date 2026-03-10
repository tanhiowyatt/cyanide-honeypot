import queue
import threading
import time
from abc import ABC, abstractmethod
from typing import Any, Dict


class OutputPlugin(ABC):
    """
    Base class for all Cyanide output plugins.
    Implements a background thread with a thread-safe queue to ensure
    that slow network/database operations do not block the main honeypot emulator.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.queue: queue.Queue = queue.Queue(maxsize=10000)
        self.running = False
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)

    def start(self):
        """Start the background worker thread."""
        self.running = True
        self.worker_thread.start()

    def stop(self):
        """Stop the background worker thread and flush the queue."""
        self.running = False
        # Block until queue is empty or timeout
        start_time = time.time()
        while not self.queue.empty() and time.time() - start_time < 5.0:
            time.sleep(0.1)

    def emit(self, event: Dict[str, Any]):
        """Enqueue an event for processing. Called by CyanideLogger."""
        if not self.running:
            return

        try:
            self.queue.put_nowait(event)
        except queue.Full:
            # Drop event if queue is full to prevent memory exhaustion
            pass

    def _worker_loop(self):
        """Background thread loop to pull events and construct batches if necessary."""
        while self.running or not self.queue.empty():
            try:
                # Use a timeout so we can periodically check self.running
                event = self.queue.get(timeout=1.0)
                try:
                    self.write(event)
                except Exception:
                    # Specific plugins should handle their own logging of write failures
                    pass
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue

    @abstractmethod
    def write(self, event: Dict[str, Any]):
        """
        Write a single event to the destination.
        Must be implemented by subclasses.
        """
        pass
