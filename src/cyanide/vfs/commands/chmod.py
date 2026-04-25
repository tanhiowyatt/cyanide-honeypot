import asyncio

from .base import Command


class ChmodCommand(Command):
    async def execute(self, args: list[str], input_data: str = "") -> tuple[str, str, int]:
        await asyncio.sleep(0)
        if len(args) < 2:
            return "", "chmod: missing operand\n", 1

        mode_arg = args[0]
        targets = args[1:]

        for target in targets:
            path = self.emulator.resolve_path(target)
            node = self.fs.get_node(path)
            if not node:
                return "", f"chmod: cannot access '{target}': No such file or directory\n", 1

            perms = list(node.perm[1:])
            if mode_arg.isdigit():
                perms = self._apply_octal_mode(mode_arg, perms)
            else:
                perms = self._apply_relative_mode(mode_arg, perms)

            self.fs.chmod(path, node.perm[0] + "".join(perms))

        return "", "", 0

    def _apply_octal_mode(self, mode_arg: str, perms: list) -> list:
        try:
            oct_val = int(mode_arg, 8)
            return self._octal_to_str(oct_val)
        except ValueError:
            return perms

    def _apply_relative_mode(self, mode_arg: str, perms: list) -> list:
        import re

        match = re.match(r"([ugoa]*)([+-=])([rwx]*)", mode_arg)
        if not match:
            return perms

        who, op, what = match.groups()
        if not who or "a" in who:
            who = "ugo"

        new_perms = list(perms)
        for w in who:
            self._update_perm_group(new_perms, w, op, what)
        return new_perms

    def _update_perm_group(self, perms: list, group: str, op: str, what: str):
        """Update a specific permission group (u, g, or o) based on operator."""
        start_idx = {"u": 0, "g": 3, "o": 6}[group]
        for i, char in enumerate("rwx"):
            if char in what:
                if op == "+":
                    perms[start_idx + i] = char
                elif op in ("-", "="):
                    perms[start_idx + i] = char if op == "=" else "-"
            elif op == "=":
                perms[start_idx + i] = "-"

    def _octal_to_str(self, octal: int) -> list:
        """Convert octal mode (e.g. 0o755) to string list (e.g. ['r','w','x','r','-','x','r','-','x'])."""
        res = []
        for i in range(2, -1, -1):
            digit = (octal >> (i * 3)) & 0o7
            res.append("r" if digit & 4 else "-")
            res.append("w" if digit & 2 else "-")
            res.append("x" if digit & 1 else "-")
        return res
