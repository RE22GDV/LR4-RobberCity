"""
Перехресна перевірка двох незалежних реалізацій (Python і C#).

Тести автоматично пропускаються, якщо .NET SDK не встановлено.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from robbercity import break_transcript, from_hex, to_hex

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PROJECT = ROOT / "csharp" / "Robber"
CASES = json.loads((HERE / "official_cases.json").read_text(encoding="utf-8"))["cases"]
IDS = [c["label"] for c in CASES]

dotnet_required = pytest.mark.skipif(
    shutil.which("dotnet") is None, reason=".NET SDK не встановлено"
)


def _run_csharp(args: list[str], stdin: str | None = None) -> str:
    # Явне UTF-8: програма на C# сама виставляє Console.OutputEncoding,
    # тож покладатися на локаль консолі Windows не можна.
    proc = subprocess.run(
        ["dotnet", "run", "--project", str(PROJECT), "--"] + args,
        input=stdin, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.rstrip("\n")


@dotnet_required
def test_csharp_selftest_passes() -> None:
    out = _run_csharp(["selftest"])
    assert "пройдено 6 з 6" in out
    assert "2000 з 2000" in out
    assert "FAIL" not in out


@dotnet_required
@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_both_implementations_agree(case: dict) -> None:
    """Режим CodinGame: той самий вхід має давати той самий відкритий текст."""
    assert _run_csharp([], stdin=case["input"] + "\n") == case["expected"]


@dotnet_required
@pytest.mark.parametrize("case", CASES[:3], ids=IDS[:3])
def test_both_implementations_recover_the_same_keys(case: dict) -> None:
    lines = _run_csharp(["break"] + case["messages"]).splitlines()
    assert lines[0] == case["expected"]
    assert lines[1] == case["alice_key"]
    assert lines[2] == case["bob_key"]


@dotnet_required
def test_python_breaks_a_session_generated_by_csharp() -> None:
    """
    Найсильніша з перехресних перевірок: сеанс породжує одна реалізація
    (з власним генератором випадкових чисел), а ламає інша.
    """
    text = "Cross implementation check, round trip"
    lines = _run_csharp(["protocol", text]).splitlines()
    assert len(lines) == 3

    messages = tuple(from_hex(line) for line in lines)
    result = break_transcript(messages)
    assert result.text == text
    # Ключі невідомі ззовні, але вони зобов'язані відтворювати трафік.
    assert to_hex(result.alice_key) != to_hex(result.bob_key)
