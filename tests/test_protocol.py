"""
Сам протокол: він має бути коректним.

Важливо показати, що зламано робочий, а не зіпсований протокол. Якщо
Боб не отримує вихідного тексту, обговорювати нічого; тому коректність
перевіряється окремо від атаки.
"""

from __future__ import annotations

import random

import pytest

from robbercity import (
    byte_entropy,
    decrypt,
    from_text,
    random_key,
    run_protocol,
    verify_transcript,
    xor_bytes,
)

RNG = random.Random(777)


@pytest.mark.parametrize("n", [1, 5, 32, 250])
def test_bob_recovers_the_message(n: int) -> None:
    """Крок 4 протоколу: Боб знімає свій ключ і має прочитати текст."""
    message = bytes(RNG.randrange(32, 127) for _ in range(n))
    t = run_protocol(message)
    assert decrypt(t.message3, t.bob_key) == message


def test_transcript_follows_the_protocol() -> None:
    for _ in range(50):
        t = run_protocol(bytes(RNG.randrange(256) for _ in range(40)))
        assert verify_transcript(t)


def test_keys_can_appear_in_traffic_when_message_is_zero() -> None:
    """
    Протокол не передбачає окремого кроку, на якому ключ передавався б
    відкритим виглядом. Але це не означає, що ключ ніколи не опиняється в
    каналі: якщо M = 0, то m1 = A і m3 = B. Загальніше, кожен нульовий байт
    повідомлення відкриває відповідні байти обох ключів.
    """
    zero = bytes(16)
    t = run_protocol(zero)
    assert t.message1 == t.alice_key
    assert t.message3 == t.bob_key

    t = run_protocol(b"ab\x00cd")
    assert t.message1[2] == t.alice_key[2]
    assert t.message3[2] == t.bob_key[2]


def test_each_transmission_looks_random() -> None:
    """
    Кожне окреме повідомлення — це текст, накладений на випадковий ключ,
    тож саме собою воно не несе жодної статистики відкритого тексту.
    Перевіряємо ентропією: один шифротекст має бути ближчим до
    випадкових байтів, ніж до тексту.
    """
    message = from_text("A" * 200)          # найгірший випадок: ентропія 0
    t = run_protocol(message)
    assert byte_entropy(message) < 1.0
    for sent in t.intercepted:
        assert byte_entropy(sent) > 6.0


def test_protocol_requires_keys_of_message_length() -> None:
    with pytest.raises(ValueError, match="завдовжки з повідомлення"):
        run_protocol(b"abcdef", random_key(3), random_key(6))


def test_protocol_accepts_explicit_keys() -> None:
    """Задані ключі мають давати відтворюваний трафік — потрібно для тестів."""
    message, alice, bob = b"abcdef", b"123456", b"ABCDEF"
    first = run_protocol(message, alice, bob)
    second = run_protocol(message, alice, bob)
    assert first.intercepted == second.intercepted
    assert first.message1 == xor_bytes(message, alice)


def test_order_of_locks_does_not_matter() -> None:
    """
    Схема працює саме тому, що «замки» комутують. Якби Аліса зняла свій
    ключ не на третьому кроці, а пізніше, результат був би той самий.
    """
    message, alice, bob = b"commutative!", random_key(12), random_key(12)
    direct = xor_bytes(xor_bytes(xor_bytes(message, alice), bob), alice)
    swapped = xor_bytes(xor_bytes(xor_bytes(message, bob), alice), alice)
    assert direct == swapped == xor_bytes(message, bob)
