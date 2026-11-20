# SQWatch

*A Lightweight File System Monitor and Task Automation Tool*

Monitor files and directories for changes, execute commands automatically, and track modifications with built-in diff and logging capabilities. Designed for reliable file watching with minimal overhead.

## Overview

SQWatch monitors specified files or directories for quality changes (such as modifications, creation, or deletion) and triggers custom commands when these changes are detected. It's designed to be simple, efficient, and easy to integrate into development workflows.

![sqwatch](./example/sqwatch.gif)

## Features

- File and directory monitoring
- Custom command execution
- Low resource footprint
- Simple integration with build tools
- Diff tracking (binary and text) for file changes
- Change logging with timestamps
- Atomic save detection (works with modern editors, such as helix)
- Recursive directory watching
- Automatic watch recovery
- Debounce support for rapid changes

## Dependencies

SQWatch requires:
- Linux kernel with inotify support
- GCC or compatible C compiler
- GNU Make

For Nix users, all dependencies are handled automatically through the nix-shell environment.

## Installation

If using Nix:

```bash
git clone https://github.com/cloudripper/sqwatch.git
cd sqwatch
nix-shell
```

If using make:

```bash
# Clone the repository
git clone https://github.com/cloudripper/sqwatch.git
cd sqwatch

# Build the project
make

# Install the binary to your path
sudo install -D ./sqwatch /usr/local/bin/sqwatch
```

## Usage

Basic syntax:
```bash
sqwatch -d DIR | -f FILE [options]
```

Watch:
- `-d DIR`: Directory to watch, with everything beneath it (repeatable)
- `-f FILE`: File to watch (repeatable)
- `-q EVENTS`: Events to react to, separated by commas, for example `-q modify,create` (default: `modify`)
  - `modify`: a file was written
  - `create`: a file or directory was created
  - `delete`: a file or directory was deleted
  - `move`: a file or directory was moved or renamed
  - `attrib`: mode, owner or times changed
  - `all`: all of the above

Command:
- `-c COMMAND`: Run COMMAND with `/bin/sh -c` on each change; a run still going is stopped and started again
- `-t SECONDS`: Debounce time of each file, a decimal number of seconds such as `2` or `0.25`, from 0 to 86400 (default: 1)

Diff:
- `--diff`: Show what changed in each file, from a private cache
- `-l FILE`: Also write the diffs to FILE (needs `--diff`)

Other:
- `-v`: Verbose output
- `-h`, `--help`: Display the help message

Every option is checked when sqwatch starts. A value that cannot be used ends it with exit status 1, a message that names the option and the value, and the values that option takes:

```
$ sqwatch -d src -q modfy
sqwatch: -q 'modfy': 'modfy' is not an event
-q EVENTS: one or more of modify, create, delete, move, attrib, all,
  separated by commas, for example -q modify,create
```

Examples:
```bash
# Watch a file for modifications and run a command
sqwatch -f main.c -q modify -c "gcc main.c -o program && ./program"

# Watch a directory recursively with diff tracking and logging
sqwatch -d src/ -q all --diff -l changes.log -v

# Watch directory with custom debounce time
sqwatch -d src/ -q modify -t 0.5 -c "make test"
```

## Environment Variables

- `SQWATCH_CACHE_DIR`: Custom location for diff cache files
- `XDG_CACHE_HOME`: Alternative cache directory base (defaults to ~/.cache)

## Contributing

Contributions are always welcome. Feel free to submit issues and pull requests.

