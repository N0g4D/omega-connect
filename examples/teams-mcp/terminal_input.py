"""What the demos ask at the terminal: shared by demo.py and hive_demo.py. Standard library only."""

from __future__ import annotations

import os
import re
import sys

UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")  # terminal controls, bidi overrides
_PASTE_MARKS = re.compile(r"\x1b\[20[01]~")  # what a terminal in bracketed-paste mode puts around a paste


class Stop(Exception):
    """The demo cannot go on; the reason has been printed."""


def ask(prompt: str) -> str:
    try:
        return input(UNSAFE.sub("", prompt)).strip()
    except EOFError:
        print()
        raise Stop from None


def ask_id(prompt: str, valid, why: str) -> str:
    while True:
        value = ask(prompt)
        if valid(value):
            return value
        print(f"  {why}")


def ask_hidden(prompt: str) -> str:
    """A pasted line that is not shown: the address a browser lands on after a sign-in carries a
    one-time code. At a terminal it is read key by key, without echo: a terminal in line mode takes
    no line longer than its limit (1,024 bytes on macOS, less than such an address can be), and past
    it not even Enter. Elsewhere (a pipe, a file) the line is read as it is."""
    if not sys.stdin.isatty():
        return ask(prompt)
    prompt = UNSAFE.sub("", prompt)
    try:
        import termios
        import tty
    except ImportError:  # Windows: getpass reads key by key there, without echo and without a line limit
        import getpass

        return getpass.getpass(prompt).strip()
    descriptor = sys.stdin.fileno()
    before = termios.tcgetattr(descriptor)
    typed = bytearray()
    try:
        # No echo and no line mode before the prompt shows, so that nothing pasted at its sight is
        # echoed or cut. Ctrl-C still interrupts.
        tty.setcbreak(descriptor)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            byte = os.read(descriptor, 1)
            if byte in (b"\n", b"\r"):
                break
            if byte in (b"", b"\x04"):  # the input ended, or Ctrl-D
                raise Stop
            if byte in (b"\x7f", b"\x08"):  # backspace takes the last character, all its bytes
                while typed and typed.pop() & 0xC0 == 0x80:
                    pass
            else:
                typed += byte
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, before)
        print()
    return _PASTE_MARKS.sub("", typed.decode("utf-8", errors="replace")).strip()
