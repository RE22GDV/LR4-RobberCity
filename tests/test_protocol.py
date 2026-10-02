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


def test_no_key_is_ever_transmitted() -> None:
    """
    Суть схеми: ключі не йдуть каналом. Перевіряємо, що жоден із трьох
    переданих рядків не дорівнює ключу й не містить його як підрядок.
    """
    for _ in range(50):
        t = run_protocol(bytes(RNG.randrange(256) for _ in range(40)))
        for sent in t.intercepted:
            assert sent != t.alice_key and sent != t.bob_key
            assert t.alice_key not in sent and t.bob_key not in sent


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
