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
- `-i PATTERN`: Ignore what matches PATTERN (repeatable). An ignored directory is not watched and not walked; an ignored file never triggers the command, is never diffed and never cached. PATTERN is a shell pattern (see `fnmatch(3)`). A PATTERN with a `/` is matched against the path below the watched directory (`/` is only matched by `/`), any other against the name alone; a trailing `/` is dropped. For example `-i '*.o' -i build/tmp`. Always ignored: `.git`, and sqwatch's own log file and cache directory when they are inside a watched tree. Ignores apply at startup, to entries created or moved in later, and when the tree is walked again after lost events

Command:
- `-c COMMAND`: Run COMMAND with `/bin/sh -c` on each change; a run still going is stopped and started again. Without `-c`, sqwatch runs in observe mode: it shows every event (and diff, with `--diff`) and runs nothing, with no debounce unless `-t` is given; `-w` and `-s` then only draw a warning
- `-w`: Wait for a run still going to end instead of stopping it. The changes that come while it runs lead to exactly one more run, started once it has exited (its first process, the shell). Without `-w` a run still going is stopped and the command started again
- `-s SIGNAL`: Signal that stops a run, on a restart and when sqwatch exits: a name, with or without `SIG`, in any case (`TERM`, `sigint`, `RTMIN+2`), or a number (default: `TERM`). What is left of the run's process group gets `KILL` 2 s later on a restart, 5 s later (or at a second signal to sqwatch) on exit. `STOP`, `TSTP`, `TTIN` and `TTOU` are refused, as they would pause the command instead of stopping it, and so is `CONT`, which stops nothing
- The command gets the change that started it in its environment, never in the command string:
  - `SQWATCH_PATH`: the path of the file or directory, as sqwatch shows it (relative to the `-d` or `-f` path given), byte for byte
  - `SQWATCH_EVENT`: `modify`, `create`, `delete`, `move` or `attrib`; `overflow`, with an empty `SQWATCH_PATH`, when events were lost and the tree was walked again without `--diff`

  Quote them: `sqwatch -d src -c 'echo "changed: $SQWATCH_PATH ($SQWATCH_EVENT)"'`. When changes come together (in one batch of events, or inside the debounce window of the last run), they lead to one run, and that run gets the latest of them.
- `-t SECONDS`: Debounce time of each file, a decimal number of seconds such as `2` or `0.25`, from 0 to 86400 (default: 1, or 0 in observe mode)

sqwatch writes its output a line at a time, whether to a terminal, a pipe or a file, and flushes it before it starts the command, so that its lines and the command's stay in order and none is written twice.

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

