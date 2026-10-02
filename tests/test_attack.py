"""
Атака та її теоретичне обґрунтування.

Тут перевіряється не лише те, що злам працює, а й чому: система над
GF(2) має повний ранг. Окремо перевіряється зворотне твердження — двох
перехоплень не досить, і це не питання обчислювальної складності, а
точна властивість.
"""

from __future__ import annotations

import random

import pytest

from robbercity import (
    MESSAGE_ROWS,
    break_transcript,
    from_text,
    recover_keys,
    recover_message,
    recoverable,
    run_protocol,
    span_gf2,
    subset_recovery_table,
    verify_transcript,
    xor_bytes,
)

RNG = random.Random(4242)

MESSAGE_MASK, ALICE_MASK, BOB_MASK = 0b100, 0b010, 0b001


def _text(n: int) -> bytes:
    return bytes(RNG.randrange(32, 127) for _ in range(n))


# --------------------------------------------------------------------------- #
#  Лінійна алгебра над GF(2)
# --------------------------------------------------------------------------- #

def test_rows_match_the_protocol() -> None:
    """Коефіцієнти рядків мають відповідати тому, що реально йде каналом."""
    assert MESSAGE_ROWS == (0b110, 0b111, 0b101)


def test_full_system_has_rank_three() -> None:
    """Три повідомлення -> оболонка з 2^3 = 8 елементів, тобто повний ранг."""
    assert len(span_gf2(MESSAGE_ROWS)) == 8


def test_message_and_both_keys_are_recoverable_from_all_three() -> None:
    for target in (MESSAGE_MASK, ALICE_MASK, BOB_MASK):
        assert recoverable(MESSAGE_ROWS, target)


@pytest.mark.parametrize("pair", [(0, 1), (0, 2), (1, 2)])
def test_message_is_not_recoverable_from_any_two(pair: tuple[int, int]) -> None:
    """
    Головне теоретичне твердження роботи: будь-які два перехоплення не
    містять інформації про повідомлення.
    """
    rows = tuple(MESSAGE_ROWS[i] for i in pair)
    assert len(span_gf2(rows)) == 4           # ранг 2
    assert not recoverable(rows, MESSAGE_MASK)


def test_each_pair_leaks_exactly_one_key_combination() -> None:
    """
    Два перехоплення все ж не марні: вони видають ключовий матеріал.
    m1,m2 -> ключ Боба; m2,m3 -> ключ Аліси; m1,m3 -> лише їх суму.
    """
    expected = {
        (0, 1): BOB_MASK,
        (1, 2): ALICE_MASK,
        (0, 2): ALICE_MASK ^ BOB_MASK,
    }
    for pair, leaked in expected.items():
        rows = tuple(MESSAGE_ROWS[i] for i in pair)
        assert recoverable(rows, leaked)
        assert not recoverable(rows, MESSAGE_MASK)


def test_single_message_leaks_nothing() -> None:
    for row in MESSAGE_ROWS:
        reach = span_gf2((row,))
        assert reach == {0, row}
        assert MESSAGE_MASK not in reach


def test_subset_table_is_consistent() -> None:
    """Таблиця зі звіту будується обчисленням і має містити рівно 7 рядків."""
    table = subset_recovery_table()
    assert len(table) == 7
    full = [r for r in table if len(r["messages"]) == 3]
    assert len(full) == 1 and full[0]["rank"] == 3 and full[0]["message_recoverable"]
    assert all(not r["message_recoverable"] for r in table if len(r["messages"]) < 3)


# --------------------------------------------------------------------------- #
#  Власне злам
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [1, 2, 17, 64, 250])
def test_attack_recovers_message_and_both_keys(n: int) -> None:
    message = _text(n)
    transcript = run_protocol(message)
    assert verify_transcript(transcript)

    result = break_transcript(transcript)
    assert result.message == message
    assert result.alice_key == transcript.alice_key
    assert result.bob_key == transcript.bob_key


def test_attack_uses_only_intercepted_data() -> None:
    """
    Атака не має права зазирати в поля з ключами. Перевіряємо, передавши
    лише три перехоплені повідомлення як звичайний кортеж.
    """
    message = _text(40)
    transcript = run_protocol(message)
    result = break_transcript(transcript.intercepted)
    assert result.message == message


def test_recovered_keys_reproduce_the_traffic() -> None:
    """
    Незалежна перевірка: відновленими ключами можна відтворити весь
    перехоплений трафік. Це сильніше за просто «текст збігся».
    """
    for _ in range(100):
        message = _text(RNG.randrange(1, 80))
        t = run_protocol(message)
        m1, m2, m3 = t.intercepted
        alice, bob = recover_keys(m1, m2, m3)
        plain = recover_message(m1, m2, m3)
        assert xor_bytes(plain, alice) == m1
        assert xor_bytes(m1, bob) == m2
        assert xor_bytes(plain, bob) == m3


def test_attack_rejects_messages_of_different_length() -> None:
    with pytest.raises(ValueError, match="різну довжину"):
        break_transcript((b"abcd", b"abcd", b"ab"))


def test_two_messages_leave_the_plaintext_undetermined() -> None:
    """
    Практичне підтвердження теоретичного твердження.

    Маючи m1 і m2, для БУДЬ-ЯКОГО відкритого тексту потрібної довжини
    існує пара ключів, узгоджена зі спостереженням. Тобто перехоплення
    не звужує множину можливих текстів узагалі.
    """
    message = from_text("Attack at dawn!!")
    t = run_protocol(message)
    m1, m2 = t.message1, t.message2

    for candidate_text in (b"Attack at dawn!!", b"Retreat at noon!", b"0000000000000000"):
        candidate_alice = xor_bytes(m1, candidate_text)   # A' = m1 + M'
        candidate_bob = xor_bytes(m1, m2)                 # B визначається однозначно
        # Сеанс із цими ключами дає рівно той самий спостережений трафік.
        replay = run_protocol(candidate_text, candidate_alice, candidate_bob)
        assert replay.message1 == m1
        assert replay.message2 == m2
