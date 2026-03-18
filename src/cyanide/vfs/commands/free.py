from .base import Command


class FreeCommand(Command):
    # Function 234: Executes the 'free' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        import secrets

        is_mb = "-m" in args
        total = 8192 if is_mb else 8388608

        rng = secrets.SystemRandom()

        used_percent = rng.uniform(0.2, 0.6)
        used = int(total * used_percent)

        shared = rng.randint(10, 100) if is_mb else rng.randint(10240, 102400)

        buff_cache_percent = rng.uniform(0.1, 0.3)
        buff_cache = int(total * buff_cache_percent)

        free = total - used - buff_cache
        available = total - used - (shared // 2)

        swap_total = 2048 if is_mb else 2097152
        swap_used = rng.randint(0, 100) if is_mb else rng.randint(0, 102400)
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
