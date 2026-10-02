"""
Злам без знання протоколу та надійність розпізнавача тексту.

Розв'язок задачі користується підказкою з умови. Тут перевіряється, що
підказка не потрібна: правильна комбінація знаходиться перебором усіх
семи варіантів і впізнається мовною моделлю.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from robbercity.analysis import MIN_LETTER_RATIO, MIN_PLAUSIBILITY
from robbercity import (
    all_combinations,
    discover,
    from_hex,
    letter_ratio,
    looks_like_english,
    plausibility,
    printable_ratio,
    run_protocol,
)

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "tests" / "official_cases.json").read_text(encoding="utf-8"))["cases"]
IDS = [c["label"] for c in CASES]
RNG = random.Random(31337)


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_blind_attack_finds_the_right_combination(case: dict) -> None:
    messages = tuple(from_hex(h) for h in case["messages"])
    best = discover(messages)
    assert best.indices == (1, 2, 3)
    assert best.text == case["expected"]


@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_correct_combination_wins_by_a_wide_margin(case: dict) -> None:
    """
    Рішення має бути не лише правильним, а й упевненим: відрив
    правильного кандидата від найкращого хибного — не випадковість.
    """
    ranked = all_combinations(tuple(from_hex(h) for h in case["messages"]))
    assert ranked[0].indices == (1, 2, 3)
    assert ranked[0].score - ranked[1].score > 20.0


def test_exactly_seven_candidates() -> None:
    """Непорожніх підмножин трьох повідомлень рівно 2^3 - 1."""
    messages = tuple(from_hex(h) for h in CASES[0]["messages"])
    assert len(all_combinations(messages)) == 7


def test_blind_attack_on_generated_sessions() -> None:
    """Те саме на власних сеансах із випадковими ключами."""
    texts = [
        b"The quick brown fox jumps over the lazy dog",
        b"Meet me at the old bridge at midnight, come alone",
        b"Report says the shipment arrives on Tuesday morning",
    ]
    for text in texts:
        transcript = run_protocol(text)
        best = discover(transcript.intercepted)
        assert best.indices == (1, 2, 3)
        assert best.data == text


def test_discovery_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="різну довжину"):
        all_combinations((b"abcd", b"abcd", b"ab"))


def test_discovery_rejects_empty_input() -> None:
    with pytest.raises(ValueError):
        all_combinations(())


# --------------------------------------------------------------------------- #
#  Надійність самого розпізнавача
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("case", CASES, ids=IDS)
def test_real_plaintext_is_recognised(case: dict) -> None:
    assert looks_like_english(case["expected"].encode("ascii"))


def test_random_bytes_are_rejected() -> None:
    """Випадкові байти не мають проходити розпізнавач жодного разу."""
    for _ in range(2000):
        data = bytes(RNG.randrange(256) for _ in range(40))
        assert not looks_like_english(data)


def test_random_printable_text_is_rejected() -> None:
    """
    Складніший випадок: випадкові ДРУКОВАНІ символи. Поодинці ні частка
    літер, ні квадриграми їх упевнено не відсікають, тому перевіряється
    саме кон'юнкція умов.
    """
    for _ in range(2000):
        data = bytes(RNG.randrange(0x20, 0x7F) for _ in range(40))
        assert not looks_like_english(data)


def test_neither_criterion_alone_is_enough() -> None:
    """
    Чому розпізнавач перевіряє дві умови, а не одну.

    Поодинці кожна межа помиляється на випадкових ДРУКОВАНИХ рядках:
    частка літер пропускає близько десятої частини з них, квадриграми —
    рідкісні одиниці. Разом вони не пропускають жодного. Тобто дві
    слабкі ознаки дають одну надійну, і це вимірюється, а не
    стверджується.
    """
    fake = [bytes(RNG.randrange(0x20, 0x7F) for _ in range(60)) for _ in range(2000)]

    by_letters = sum(letter_ratio(d) >= MIN_LETTER_RATIO for d in fake)
    by_score = sum(plausibility(d) > MIN_PLAUSIBILITY for d in fake)
    by_both = sum(looks_like_english(d) for d in fake)

    assert by_letters > 0, "межа за часткою літер мала б іноді помилятися"
    assert by_both == 0
    assert by_both <= by_letters and by_both <= by_score


def test_real_texts_pass_both_criteria_with_margin() -> None:
    """А справжні тексти задачі проходять обидві умови, і не впритул."""
    for case in CASES:
        data = case["expected"].encode("ascii")
        assert printable_ratio(data) == 1.0
        assert letter_ratio(data) >= MIN_LETTER_RATIO
        assert plausibility(data) > MIN_PLAUSIBILITY


def test_printable_ratio_of_random_bytes_is_about_37_percent() -> None:
    """
    Друковані байти займають 95 значень із 256, тобто 37,1 %. Саме тому
    перша умова розпізнавача така дешева й така ефективна.
    """
    data = bytes(RNG.randrange(256) for _ in range(20000))
    assert 0.34 < printable_ratio(data) < 0.40
