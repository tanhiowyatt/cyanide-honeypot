from .base import Command


class FreeCommand(Command):
    async def execute(self, args, input_data=""):
        import random

        # Base total memory (8GB by default)
        is_mb = "-m" in args
        total = 8192 if is_mb else 8388608

        # Randomize used memory (20-60%)
        used_percent = random.uniform(0.2, 0.6)
        used = int(total * used_percent)

        # Randomize shared (very low)
        shared = random.randint(10, 100) if is_mb else random.randint(10240, 102400)

        # Randomize buff/cache (10-30%)
        buff_cache_percent = random.uniform(0.1, 0.3)
        buff_cache = int(total * buff_cache_percent)

        # Calculate free and available
        free = total - used - buff_cache
        available = total - used - (shared // 2)  # simplified linux available memory heuristic

        # Swap (usually 2GB)
        swap_total = 2048 if is_mb else 2097152
        swap_used = random.randint(0, 100) if is_mb else random.randint(0, 102400)
        swap_free = swap_total - swap_used

        return (
            (
                "              total        used        free      shared  buff/cache   available\n"
                f"Mem:           {total:<11} {used:<11} {free:<11} {shared:<10} {buff_cache:<11} {available:<11}\n"
                f"Swap:          {swap_total:<11} {swap_used:<11} {swap_free:<11}\n"
            ),
            "",
            0,
        )
