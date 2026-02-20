from .base import Command


class AliasCommand(Command):
    async def execute(self, args, input_data=""):
        if not args:
            return (
                (
                    "alias l='ls -CF'\n"
                    "alias la='ls -A'\n"
                    "alias ll='ls -alF'\n"
                    "alias ls='ls --color=auto'\n"
                ),
                "",
                0,
            )
        # Mocks don't store aliases for now
        return "", "", 0
