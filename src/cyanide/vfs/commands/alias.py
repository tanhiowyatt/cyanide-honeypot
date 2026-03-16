from .base import Command


class AliasCommand(Command):
    # Function 202: Executes the 'alias' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        if not args:
            output = ""
            for k in sorted(self.emulator.aliases.keys()):
                output += f"alias {k}='{self.emulator.aliases[k]}'\n"
            return output, "", 0

        output = ""
        rc = 0
        for arg in args:
            if "=" in arg:
                parts = arg.split("=", 1)
                name = parts[0]
                value = parts[1]

                if len(value) >= 2 and (
                    (value.startswith("'") and value.endswith("'"))
                    or (value.startswith('"') and value.endswith('"'))
                ):
                    value = value[1:-1]

                self.emulator.aliases[name] = value
            else:
                if arg in self.emulator.aliases:
                    output += f"alias {arg}='{self.emulator.aliases[arg]}'\n"
                else:
                    output += f"bash: alias: {arg}: not found\n"
                    rc = 1

        return output, "", rc


class UnaliasCommand(Command):
    # Function 203: Executes the 'alias' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        if not args:
            return "", "unalias: usage: unalias name [name ...]\n", 1

        rc = 0
        for arg in args:
            if arg in self.emulator.aliases:
                del self.emulator.aliases[arg]
            else:
                return "", f"bash: unalias: {arg}: not found\n", 1

        return "", "", rc
