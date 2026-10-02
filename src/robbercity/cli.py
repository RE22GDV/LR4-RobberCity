"""
Командний інтерфейс роботи.

    python run.py selftest            офіційні тести CodinGame
    python run.py break <m1> <m2> <m3>  злам трьох перехоплених повідомлень
    python run.py blind <m1> <m2> <m3>  злам без знання протоколу
    python run.py demo [текст]          згенерувати сеанс і зламати його
    python run.py table                 що дає перехоплення кожної підмножини
    python run.py shamir [текст]        правильна реалізація того ж протоколу
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import byte_entropy
from .attack import break_transcript, subset_recovery_table
from .discovery import all_combinations
from .protocol import run_protocol
from .shamir import run_shamir, xor_style_attack
from .xorcipher import from_hex, from_text, to_hex

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "tests" / "official_cases.json"


def _print(text: str = "") -> None:
    sys.stdout.write(text + "\n")


# --------------------------------------------------------------------------- #

def cmd_selftest(_args) -> int:
    """Прогнати всі офіційні тести платформи."""
    data = json.loads(CASES.read_text(encoding="utf-8"))["cases"]
    line = "-" * 78
    _print("Офіційні тести CodinGame")
    _print(line)
    passed = 0
    for i, case in enumerate(data, 1):
        messages = tuple(from_hex(h) for h in case["messages"])
        result = break_transcript(messages)
        ok = result.text == case["expected"]
        keys_ok = (to_hex(result.alice_key) == case["alice_key"]
                   and to_hex(result.bob_key) == case["bob_key"])
        passed += ok and keys_ok
        preview = result.text if len(result.text) <= 44 else result.text[:41] + "..."
        _print("[%s] Test %d  %3d байт  ключі %s  %s"
               % ("OK" if ok and keys_ok else "FAIL", i, case["length_bytes"],
                  "+" if keys_ok else "-", preview))
    _print(line)
    _print("Пройдено %d з %d" % (passed, len(data)))
    return 0 if passed == len(data) else 1


def cmd_break(args) -> int:
    """Зламати три перехоплені повідомлення."""
    messages = tuple(from_hex(h) for h in args.messages)
    result = break_transcript(messages)
    _print("Відкритий текст : %s" % result.text)
    _print("Ключ Аліси      : %s" % to_hex(result.alice_key))
    _print("Ключ Боба       : %s" % to_hex(result.bob_key))
    _print("Довжина         : %d байт" % len(result.message))
    return 0


def cmd_blind(args) -> int:
    """Знайти відкритий текст перебором комбінацій, не знаючи протоколу."""
    messages = tuple(from_hex(h) for h in args.messages)
    _print("Кандидати, впорядковані мовною моделлю:")
    _print("-" * 78)
    for cand in all_combinations(messages):
        text = cand.text
        preview = "-" if text is None else (
            text if len(text) <= 36 else text[:33] + "...")
        _print("%-22s оцінка %7.2f  друковані %5.1f %%  %s"
               % (cand.label, cand.score, 100 * cand.printable, preview))
    _print("-" * 78)
    _print("Відповідь: %s" % all_combinations(messages)[0].text)
    return 0


def cmd_demo(args) -> int:
    """Згенерувати власний сеанс із випадковими ключами й зламати його."""
    message = from_text(args.text)
    transcript = run_protocol(message)
    _print("Повідомлення    : %s" % args.text)
    _print("Ключ Аліси      : %s" % to_hex(transcript.alice_key))
    _print("Ключ Боба       : %s" % to_hex(transcript.bob_key))
    _print()
    for i, line in enumerate(transcript.as_hex_lines(), 1):
        _print("m%d (у каналі)   : %s" % (i, line))
    _print()
    result = break_transcript(transcript)
    _print("Відновлено текст: %s" % result.text)
    _print("Відновлено A    : %s  %s"
           % (to_hex(result.alice_key),
              "збіг" if result.alice_key == transcript.alice_key else "РОЗБІЖНІСТЬ"))
    _print("Відновлено B    : %s  %s"
           % (to_hex(result.bob_key),
              "збіг" if result.bob_key == transcript.bob_key else "РОЗБІЖНІСТЬ"))
    _print()
    _print("Ентропія ключа Аліси: %.2f біта/байт (рівномірна межа — 8,00)"
           % byte_entropy(transcript.alice_key))
    return 0


def cmd_table(_args) -> int:
    """Показати, що дає перехоплення кожної підмножини повідомлень."""
    _print("Перехоплено   Ранг   Повідомлення   Що відновлюється")
    _print("-" * 64)
    for row in subset_recovery_table():
        _print("%-13s %-6d %-14s %s"
               % (", ".join("m%d" % i for i in row["messages"]),
                  row["rank"],
                  "так" if row["message_recoverable"] else "ні",
                  ", ".join(row["recovered"]) or "нічого"))
    _print("-" * 64)
    _print("Повідомлення відновлюється лише за наявності всіх трьох перехоплень.")
    return 0


def cmd_shamir(args) -> int:
    """Та сама схема на піднесенні до степеня: злам із роботи не спрацьовує."""
    message = from_text(args.text)
    transcript = run_shamir(message)
    _print("Повідомлення          : %s" % args.text)
    _print("Модуль                : просте MODP-2048 (RFC 3526)")
    for i, value in enumerate(transcript.intercepted, 1):
        _print("m%d (у каналі, hex)    : %s..." % (i, format(value, "x")[:48]))
    guess = xor_style_attack(transcript)
    _print()
    _print("Мультиплікативний аналог m1 xor m2 xor m3 дає:")
    _print("  %s..." % guess.hex()[:48])
    _print("  як текст ASCII: %s"
           % ("не декодується" if any(b > 127 for b in guess) else repr(guess.decode())))
    _print("  збіг із повідомленням: %s" % ("так" if guess == message else "ні"))
    return 0


# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="robbercity", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest", help="офіційні тести CodinGame").set_defaults(
        func=cmd_selftest)

    for name, func, helptext in (
        ("break", cmd_break, "зламати три перехоплені повідомлення"),
        ("blind", cmd_blind, "злам без знання протоколу"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("messages", nargs=3, metavar=("M1", "M2", "M3"))
        p.set_defaults(func=func)

    p = sub.add_parser("demo", help="згенерувати сеанс і зламати його")
    p.add_argument("text", nargs="?", default="Meet me at the old bridge at midnight")
    p.set_defaults(func=cmd_demo)

    sub.add_parser("table", help="що дає кожна підмножина перехоплень").set_defaults(
        func=cmd_table)

    p = sub.add_parser("shamir", help="правильна реалізація того ж протоколу")
    p.add_argument("text", nargs="?", default="The lock idea itself is fine")
    p.set_defaults(func=cmd_shamir)

    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
