"""What the demos ask at the terminal: shared by demo.py and hive_demo.py. Standard library only."""

from __future__ import annotations

import re

UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")  # terminal controls, bidi overrides


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
