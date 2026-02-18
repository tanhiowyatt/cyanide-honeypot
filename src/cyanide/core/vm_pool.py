import random


class VMPool:
    """
    Manages a pool of backend VM addresses (e.g., QEMU instances).
    Provides targets for the proxy services.
    """

    def __init__(self, config):
        """
        Initialize the pool from config.
        Expects config['pool']['targets'] to be a comma-separated list of "host:port".
        """
        self.targets = []
        pool_conf = config.get("pool", {})
        target_str = pool_conf.get("targets", "")

        if target_str:
            for t in target_str.split(","):
                pass_parts = t.strip().split(":")
                if len(pass_parts) == 2:
                    self.targets.append((pass_parts[0], int(pass_parts[1])))
                elif len(pass_parts) == 1:
                    # Default port? Assume SSH 22 or passed in context.
                    # For simplicity, require port or use default 22
                    self.targets.append((pass_parts[0], 22))

    def get_target(self):
        """
        Get a target (host, port) from the pool.
        Strategies: Random, Round-Robin.
        Currently: Random.
        """
        if not self.targets:
            return None
        return random.choice(self.targets)

    def report_failure(self, host, port):
        """
        Report a failed backend. Could disable it temporarily.
        """
        # Placeholder for health checking logic
        print(f"[!] VM Pool: Backend {host}:{port} reported failure.")
