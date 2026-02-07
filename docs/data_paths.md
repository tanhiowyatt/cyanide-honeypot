# Data Paths Documentation

This document explains the purpose and structure of the static data directories used by Cyanide Honeypot.

## `fs_pickle` (Filesystem Snapshot)

**Configuration Key:** `FS_PICKLE` (env) or `fs_pickle` (cfg)
**Default Path:** `data/cyanide/fs.pickle`

### Purpose
The `fs.pickle` file contains a serialized Python object representing the initial state of the emulated filesystem. When a new SSH or Telnet session starts, the honeypot loads this object to create a fresh, isolated filesystem instance for that session.

### Structure
- **Format:** Python `pickle` protocol.
- **Content:** A root `Directory` node containing all subdirectories and files (e.g., `/etc`, `/bin`, `/home`).
- **Persistence:** Changes made by attackers during a session are NOT saved back to this file. They are kept in memory for the duration of the session and discarded afterwards (though logged via TTY logs).

## `txtcmds_path` (Text Commands)

**Configuration Key:** `TXTCMDS_PATH` (env) or `txtcmds_path` (cfg)
**Default Path:** `data/cyanide/txtcmds`

### Purpose
This directory contains text files that define the static output for specific commands. It allows for easy extension of the honeypot's capabilities without writing Python code for every command.

### Usage
- When a user executes a command (e.g., `cpuinfo`), the shell emulator checks this directory.
- If a file matches the command name (e.g., `cpuinfo.txt`), its content is returned as the command's standard output.

### Directory Structure
```
data/cyanide/txtcmds/
├── cpuinfo         # Output for 'cat /proc/cpuinfo' or similar
├── meminfo         # Output for 'cat /proc/meminfo'
├── version         # Output for 'cat /proc/version'
└── ...
```

### Extending
To add a static response for a new command:
1. Create a file in `data/cyanide/txtcmds/` with the command name.
2. Paste the desired output into the file.
