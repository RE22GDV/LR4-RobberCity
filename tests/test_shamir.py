"""
Правильна реалізація того самого протоколу.

Мета цих тестів — підтвердити головну тезу роботи: зламано реалізацію,
а не ідею. Якщо «замком» зробити піднесення до степеня за модулем
простого числа, протокол лишається тим самим, а атака з цієї роботи
перестає працювати.
"""

from __future__ import annotations

import random
from math import gcd

import pytest

from robbercity import MODP_2048, keypair, run_shamir, xor_style_attack
from robbercity.shamir import ShamirTranscript

RNG = random.Random(99)


def test_modulus_is_odd_and_large() -> None:
    """MODP-2048 з RFC 3526: 2048 біт, безпечне просте p = 2q + 1."""
    assert MODP_2048.bit_length() == 2048
    assert MODP_2048 % 2 == 1


def test_keypair_is_invertible() -> None:
    """Показник має бути оборотним за модулем p-1, інакше замок не зняти."""
    for _ in range(5):
        a, a_inv = keypair()
        assert gcd(a, MODP_2048 - 1) == 1
        assert a * a_inv % (MODP_2048 - 1) == 1


@pytest.mark.parametrize("text", [
    b"Hello bob ! How are you ?",
    b"The lock idea itself is fine",
    b"x",
])
def test_protocol_delivers_the_message(text: bytes) -> None:
    """Сам протокол працює: перевірка вбудована в run_shamir."""
    transcript = run_shamir(text)
    assert isinstance(transcript, ShamirTranscript)
    assert len(set(transcript.intercepted)) == 3


def test_locks_commute() -> None:
    """
    Протокол тримається на комутативності: (x^a)^b = (x^b)^a.
    Саме вона дозволяє зняти замки в «неправильному» порядку.
    """
    p = MODP_2048
    x = int.from_bytes(b"commutative", "big")
    a, _ = keypair()
    b, _ = keypair()
    assert pow(pow(x, a, p), b, p) == pow(pow(x, b, p), a, p)


@pytest.mark.parametrize("text", [
    b"Hello bob ! How are you ?",
    b"Meet me at the old bridge at midnight",
])
def test_xor_style_attack_fails(text: bytes) -> None:
    """
    Мультиплікативний аналог ``m1 xor m2 xor m3`` дає ``x^(a+b-ab)``,
    що не має нічого спільного з повідомленням.
    """
    transcript = run_shamir(text)
    guess = xor_style_attack(transcript)
    assert guess != text
    assert not guess.decode("ascii", errors="ignore").startswith(text[:4].decode())


def test_attack_result_is_not_even_ascii() -> None:
    """Результат хибної атаки — шум, а не зіпсований текст."""
    guess = xor_style_attack(run_shamir(b"The lock idea itself is fine"))
    assert any(b > 127 for b in guess)


def test_message_must_fit_into_the_modulus() -> None:
    with pytest.raises(ValueError):
        run_shamir(b"\x00")                      # нуль неприпустимий
    with pytest.raises(ValueError):
        run_shamir(bytes([255]) * 300)           # більше за модуль


def test_transcript_values_are_in_range() -> None:
    transcript = run_shamir(b"range check")
    assert all(0 < value < MODP_2048 for value in transcript.intercepted)
