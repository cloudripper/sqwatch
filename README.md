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
sqwatch [-d directory] [-f file] -q event [-c command] [--diff] [-l log_file] [-t debounce_time] [-v]
```

Options:
- `-d directory`: Directory to watch (recursively)
- `-f file`: File to watch
- `-q event`: Event type to watch
  - `all`: all events
  - `modify`: file modifications
  - `create`: file creation
  - `delete`: file deletion
  - `move`: file moves
  - `attrib`: attribute changes
- `-c command`: Command to execute when events are detected
- `--diff`: Enable diff tracking for file changes
- `-l log_file`: Log file to write changes to (requires --diff)
- `-t debounce_time`: Time in seconds to wait before processing new events (default: 1)
- `-v`: Verbose output mode
- `-h`: Display help message

Examples:
```bash
# Watch a file for modifications and run a command
sqwatch -f main.c -q modify -c "gcc main.c -o program && ./program"

# Watch a directory recursively with diff tracking and logging
sqwatch -d src/ -q all --diff -l changes.log -v

# Watch directory with custom debounce time
sqwatch -d src/ -q modify -t 2 -c "make test"
```

## Environment Variables

- `SQWATCH_CACHE_DIR`: Custom location for diff cache files
- `XDG_CACHE_HOME`: Alternative cache directory base (defaults to ~/.cache)

## Contributing

Contributions are always welcome. Feel free to submit issues and pull requests.

