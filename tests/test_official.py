"""
Офіційні тести CodinGame, збережені в репозиторії.

Перевіряється і бібліотека, і самодостатній файл розв'язку, який
вставляється в редактор платформи: тест, якого немає в репозиторії,
нічого не доводить.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from robbercity import break_transcript, from_hex, to_hex, xor_bytes

ROOT = Path(__file__).resolve().parents[1]
DATA = json.loads((ROOT / "tests" / "official_cases.json").read_text(encoding="utf-8"))
CASES = DATA["cases"]
IDS = [c["label"] for c in CASES]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_fixture_is_self_consistent(case: dict) -> None:
    """
    Записані ключі мають точно відтворювати збережений трафік.

    Це ловить помилку переписування тестових даних: якби якийсь рядок
    був скопійований неправильно, узгодженість зникла б.
    """
    messages = [from_hex(h) for h in case["messages"]]
    plain = case["expected"].encode("ascii")
    alice, bob = from_hex(case["alice_key"]), from_hex(case["bob_key"])

    assert len(plain) == case["length_bytes"]
    assert all(len(m) == case["length_bytes"] for m in messages)
    assert xor_bytes(plain, alice) == messages[0]       # m1 = M + A
    assert xor_bytes(messages[0], bob) == messages[1]   # m2 = m1 + B
    assert xor_bytes(plain, bob) == messages[2]         # m3 = M + B


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_library_breaks_official_case(case: dict) -> None:
    result = break_transcript(tuple(from_hex(h) for h in case["messages"]))
    assert result.text == case["expected"]
    assert to_hex(result.alice_key) == case["alice_key"]
    assert to_hex(result.bob_key) == case["bob_key"]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_standalone_codingame_script(case: dict) -> None:
    """Файл, який вставляється в редактор CodinGame, теж має проходити тести."""
    script = ROOT / "solution" / "codingame_solution.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=case["input"] + "\n", capture_output=True, text=True,
        encoding="utf-8", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.rstrip("\n") == case["expected"]


def test_message_lengths_match_the_constraints() -> None:
    """Умова задачі: не більше 250 символів, тобто 500 шістнадцяткових цифр."""
    for case in CASES:
        assert 1 <= case["length_bytes"] <= 250, case["label"]
        assert all(len(h) == 2 * case["length_bytes"] for h in case["messages"])


def test_every_case_uses_fresh_keys() -> None:
    """
    Ключі не повторюються ні між тестами, ні між Алісою та Бобом — тобто
    зламано саме протокол, а не повторне використання блокнота.
    """
    keys = [c["alice_key"] for c in CASES] + [c["bob_key"] for c in CASES]
    assert len(set(keys)) == len(keys)


def test_last_case_leaks_a_key_for_another_cipher() -> None:
    """
    Шостий тест — найцікавіший: відновлений текст містить приватний ключ
    для наступного шифру. Злам одного повідомлення руйнує й те
    листування, яке мало б бути захищене сильнішим алгоритмом.
    """
    text = CASES[-1]["expected"]
    assert "AES" in text and "private key" in text
    assert len(text.rsplit(" ", 1)[-1]) == 64      # 256 біт у шістнадцятковому


def test_cli_selftest_command() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "run.py"), "selftest"],
        capture_output=True, text=True, encoding="utf-8", timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Пройдено 6 з 6" in proc.stdout
