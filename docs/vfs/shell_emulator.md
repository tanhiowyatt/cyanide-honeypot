# Shell Emulator Architecture (`src/cyanide/core/emulator.py`)

The `ShellEmulator` represents the highly convincing simulated Linux shell environment presented to the attacker when they successfully authenticate in an `emulated` backend mode. It does not spawn a real underlying OS process, preventing container escapes by design.

## 1. Context and State Tracking

For every incoming connection, a new `ShellEmulator` instance is created and uniquely tied to the attacker's `session_id`.

### Built-in State:
- **`cwd` (Current Working Directory):** Tracks the attacker's simulated location (`/root` by default if authenticated as root).
- **`username`:** Represents the active authenticated user, mapping to permissions checks within the VFS Engine.
- **`env`:** A transient environment variable dictionary mirroring a standard bash environment (`PATH`, `USER`, `PWD`, `HOME`). Attackers attempting to run `export` or `env` will see and modify this internal dictionary without ever affecting the real host.
- **`aliases`:** Pre-baked common Linux aliases (e.g., `ll='ls -la'`). The emulator automatically expands the first token if it matches an alias.

## 2. The Custom AST Parser

Real attackers rarely type simple single-command strings like `ls`. They upload complex scripts or chain commands heavily. To catch this, Cyanide implements a custom Abstract Syntax Tree (AST) Bash Parser.

### Execution Pipeline (`execute()`):
When a string arrives from SSH or Telnet, the emulator intercepts it immediately and parses it into execution chains.

1. **Tokenization:** Splits the command respecting single quotes `'`, double quotes `"`, and escape characters `\`.
2. **Logic Gates:** Parses typical bash logic operators:
   - `;` (Sequential execution)
   - `&&` (Logical AND - stops on failure)
   - `||` (Logical OR - continues on failure)
3. **Piping (`|`):** The emulator captures standard output from the left-hand command and overrides the standard input buffer for the right-hand command without relying on native OS `os.pipe`.
4. **Redirection (`>`, `>>`):** If output redirection is requested, the emulator halts execution, interacts with the VFS `FakeFilesystem` to create or append to the target virtual node, and funnels all output invisibly to the simulated disk.

## 3. Command Dispatch & Permissions

After AST parsing, the string resolves to an internal Python class inheriting from the VFS Command layer (`src/cyanide/vfs/commands/`).

- If the command class does not exist, the emulator returns a realistic `bash: <command>: command not found` stderr message.
- If it does exist, the emulator performs a **Permission Boundary Check**. It calls the VFS `check_permission()` to determine if `username` has execution rights over that virtual path.
- The command executes natively in python, reading/writing entirely from the VFS Memory Overlay and passing its final byte-stream back through the emulator directly into the attacker's PTY socket.
