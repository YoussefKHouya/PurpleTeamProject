#!/usr/bin/env python3
"""Normalize auditd exec events into JSON lines for Wazuh."""

import ast
import json
import os
import re
import shlex
import sys
from pathlib import Path

EVENT_RE = re.compile(r"msg=audit\(([^)]+)\)")
FIELD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|\S+)")
ARG_RE = re.compile(r"\ba(\d+)=(\"(?:\\.|[^\"])*\"|[0-9A-Fa-f]+)")
KEEP = {"success", "exit", "ppid", "pid", "auid", "uid", "gid", "euid", "tty", "comm", "exe", "key"}


def decode_value(raw: str) -> str:
    if raw.startswith(('"', "'")):
        try:
            return str(ast.literal_eval(raw))
        except (SyntaxError, ValueError):
            return raw[1:-1]
    return raw


def decode_arg(raw: str) -> str:
    if raw.startswith(('"', "'")):
        return decode_value(raw)
    if len(raw) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", raw):
        try:
            return bytes.fromhex(raw).decode("utf-8", "replace")
        except ValueError:
            pass
    return raw


def event_id(line: str) -> str | None:
    match = EVENT_RE.search(line)
    return match.group(1) if match else None


def emit(output, event: dict) -> None:
    if event.get("key") != "wazuh_shell_exec" or not event.get("argv"):
        return
    argv = event["argv"]
    event["event_source"] = "auditd_execve"
    event["command_line"] = shlex.join(argv)
    output.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")
    output.flush()


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT_JSONL", file=sys.stderr)
        return 2

    os.umask(0o027)
    path = Path(sys.argv[1])
    path.parent.mkdir(parents=True, exist_ok=True)
    pending: dict[str, dict] = {}

    with path.open("a", encoding="utf-8", buffering=1) as output:
        for raw_line in sys.stdin:
            line = raw_line.strip()
            eid = event_id(line)
            if not eid:
                continue
            event = pending.setdefault(eid, {"audit_id": eid})

            if line.startswith("type=SYSCALL"):
                for key, value in FIELD_RE.findall(line.split("\x1d", 1)[0]):
                    if key in KEEP:
                        event[key] = decode_value(value)
            elif line.startswith("type=EXECVE"):
                args = sorted((int(index), decode_arg(value)) for index, value in ARG_RE.findall(line))
                event["argv"] = [value for _, value in args]
                argc = re.search(r"\bargc=(\d+)", line)
                if argc:
                    event["argc"] = int(argc.group(1))
            elif line.startswith("type=CWD"):
                cwd = re.search(r'\bcwd=("(?:\\.|[^\"])*"|\S+)', line)
                if cwd:
                    event["cwd"] = decode_value(cwd.group(1))
            elif line.startswith("type=EOE"):
                emit(output, pending.pop(eid, event))

            if len(pending) > 2048:
                oldest = next(iter(pending))
                emit(output, pending.pop(oldest))

        for event in pending.values():
            emit(output, event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
