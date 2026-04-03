import asyncio

from .base import Command


class AliasCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        """Execute the alias command."""
        if not args:
            return self._list_aliases(), "", 0

        output = ""
        total_rc = 0
        for arg in args:
            if "=" in arg:
                self._set_alias(arg)
            else:
                out, rc = self._get_alias(arg)
                output += out
                if rc != 0:
                    total_rc = rc

        return output, "", total_rc

    def _list_aliases(self) -> str:
        """List all current aliases."""
        sorted_keys = sorted(self.emulator.aliases.keys())
        return "".join(f"alias {k}='{self.emulator.aliases[k]}'\n" for k in sorted_keys)

    def _set_alias(self, arg: str) -> None:
        """Parse and set a new alias."""
        name, value = arg.split("=", 1)
        if len(value) >= 2 and (
            (value.startswith("'") and value.endswith("'"))
            or (value.startswith('"') and value.endswith('"'))
        ):
            value = value[1:-1]
        self.emulator.aliases[name] = value

    def _get_alias(self, name: str) -> tuple[str, int]:
        """Look up a single alias."""
        if name in self.emulator.aliases:
            return f"alias {name}='{self.emulator.aliases[name]}'\n", 0
        return f"bash: alias: {name}: not found\n", 1


class UnaliasCommand(Command):
    async def execute(self, args, input_data=""):
        await asyncio.sleep(0)
        if not args:
            return "", "unalias: usage: unalias name [name ...]\n", 1

        rc = 0
        for arg in args:
            if arg in self.emulator.aliases:
                del self.emulator.aliases[arg]
            else:
                return "", f"bash: unalias: {arg}: not found\n", 1

        return "", "", rc
