# Filesystem (VFS) and Command Emulation

## VFS Overview

The core of Cyanide's interaction is its virtual filesystem. It attempts to provide a realistic Linux environment without exposing the host OS.

### Structure
The VFS is a tree of `Node` objects (`Directory`, `File`, `Symlink`).
It is initialized from YAML templates (`configs/profiles/`) at the start of each session.

### Persistence
Changes made during a session (e.g., `mkdir /tmp/test`) persist within that session's memory space.
If a user disconnects and reconnects, they get a fresh filesystem instance (unless session persistence is enabled, which is currently experimental).

---

## Command Emulation (`src/cyanide/vfs/commands`)

Cyanide does not execute commands via `os.system` or `subprocess`. Instead, it emulates the behavior of standard coreutils within the Python environment.

### Command Structure
Each command is a function or class that:
1.  Receives arguments (string list).
2.  Interacts with the `FakeFilesystem` object.
3.  Returns stdout/stderr, exit code.

### Supported Commands

| Command | Status | Notes |
|---------|--------|-------|
| `cd` | ✅ | Navigates the VFS tree. |
| `ls` | ✅ | Supports `-l`, `-a`, `-h`, color output. |
| `pwd` | ✅ | Prints current VFS path. |
| `cat` | ✅ | Reads file content from VFS. |
| `echo` | ✅ | Basic echo with variable expansion. |
| `mkdir` | ✅ | Creates directories (supports `-p`). |
| `rm` | ✅ | Removes files/dirs (supports `-rf`). |
| `cp` | ✅ | Copies files within VFS. |
| `mv` | ✅ | Moves/Renames within VFS. |
| `touch` | ✅ | create empty file or update timestamp. |
| `wget` | ✅ | Downloads file to `quarantine` and saves fake file in VFS. |
| `curl` | ✅ | Similar to wget. |
| `id` | ✅ | Shows fake UID/GID (root=0). |
| `whoami` | ✅ | Shows current fake user. |
| `uname` | ✅ | Returns kernel version from Profile Metadata. |
| `ps` | ✅ | Shows fake process list dynamically loaded from Profile Metadata. |
| `vi/vim` | ⚠️ | Starts a simple line editor simulation (trap). |

### Adding a New Command
1.  Create a new file in `src/cyanide/vfs/commands/mycmd.py`.
2.  Implement the logic interacting with `ctx.fs`.
3.  Register it in `src/cyanide/vfs/commands/__init__.py`.

---

## Dynamic System Files (`/proc`)

Cyanide supports dynamic content generation for system files. These files are re-generated every time a user reads them:

-   **/proc/uptime**: Generates realistic uptime and idle time. Uptime is randomized at startup (1 hour to 30 days) and increments naturally.
-   **/proc/meminfo**: Generates randomized memory statistics (Total, Free, Available, Buffers, Cached) based on a simulated RAM size (4GB, 8GB, or 16GB).

The contents of these files reflect the "live" state of the emulated environment.
