from .base import Command


class FingerCommand(Command):
    # Function 233: Executes the 'finger' command logic within the virtual filesystem.
    async def execute(self, args, input_data=""):
        import random
        from datetime import datetime, timedelta

        if not args:
            output = "Login     Name       Tty      Idle  Login Time   Office     Office Phone\n"

            potential_users = [
                ("root", "root"),
                ("admin", "admin Worker"),
                ("user1", "John Doe"),
                ("operator", "System Op"),
                ("service", "Service Account"),
            ]

            num_sessions = random.randint(2, 4)
            sessions = random.sample(potential_users, num_sessions)
            if ("root", "root") not in sessions and random.random() > 0.3:
                sessions[0] = ("root", "root")

            for i, (login, name) in enumerate(sessions):
                tty = f"pts/{i}"
                idle = random.choice(["", "1:20", "5s", "4:15", "1d"])

                login_dt = datetime.now() - timedelta(minutes=random.randint(10, 1440))
                login_time = login_dt.strftime("%b %d %H:%M")

                output += f"{login:<9} {name:<10} {tty:<8} {idle:<5} {login_time}\n"

            return output, "", 0
        user = args[0]
        return (
            (
                f"Login: {user}      \t\t\tName: {user}\n"
                f"Directory: /home/{user}  \t\tShell: /bin/bash\n"
                "Never logged in.\n"
                "No mail.\n"
                "No Plan.\n"
            ),
            "",
            0,
        )
