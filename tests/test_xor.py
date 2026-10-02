"""
Властивості самої операції XOR.

Саме ці властивості роблять протокол привабливим — і вони ж його
руйнують. Тому перевіряються вони явно, а не припускаються.
"""

from __future__ import annotations

import random

import pytest

from robbercity import (
    decrypt,
    encrypt,
    from_hex,
    from_text,
    random_key,
    to_hex,
    to_text,
    xor_all,
    xor_bytes,
)

RNG = random.Random(20261002)


def _blob(n: int) -> bytes:
    return bytes(RNG.randrange(256) for _ in range(n))


# --------------------------------------------------------------------------- #
#  Алгебра
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [0, 1, 2, 17, 250])
def test_xor_is_self_inverse(n: int) -> None:
    """m XOR k XOR k = m — шифрування й розшифрування є тією самою дією."""
    message, key = _blob(n), _blob(n)
    assert decrypt(encrypt(message, key), key) == message
    assert encrypt(message, key) == decrypt(message, key)


def test_xor_with_itself_is_zero() -> None:
    """A XOR A = 0 — саме це скорочує ключі в атаці."""
    data = _blob(64)
    assert xor_bytes(data, data) == bytes(64)


def test_xor_with_zero_is_identity() -> None:
    """A XOR 0 = A."""
    data = _blob(64)
    assert xor_bytes(data, bytes(64)) == data


def test_xor_is_commutative() -> None:
    for _ in range(50):
        a, b = _blob(32), _blob(32)
        assert xor_bytes(a, b) == xor_bytes(b, a)


def test_xor_is_associative() -> None:
    for _ in range(50):
        a, b, c = _blob(32), _blob(32), _blob(32)
        assert xor_bytes(xor_bytes(a, b), c) == xor_bytes(a, xor_bytes(b, c))


def test_xor_all_ignores_order() -> None:
    """Порядок аргументів не впливає на результат — наслідок двох попередніх."""
    chunks = [_blob(48) for _ in range(5)]
    reference = xor_all(*chunks)
    for _ in range(20):
        shuffled = chunks[:]
        RNG.shuffle(shuffled)
        assert xor_all(*shuffled) == reference


# --------------------------------------------------------------------------- #
#  Межові випадки
# --------------------------------------------------------------------------- #

def test_length_mismatch_is_an_error() -> None:
    """
    Мовчазне обрізання до коротшої послідовності — класичне джерело
    помилок, тому тут це помилка, а не «особливість».
    """
    with pytest.raises(ValueError, match="довжини не збігаються"):
        xor_bytes(b"abcd", b"ab")


def test_xor_all_needs_at_least_one_argument() -> None:
    with pytest.raises(ValueError):
        xor_all()


def test_odd_hex_length_is_an_error() -> None:
    with pytest.raises(ValueError, match="непарна"):
        from_hex("abc")


def test_hex_tolerates_whitespace() -> None:
    assert from_hex("de ad\nbe ef") == bytes.fromhex("deadbeef")


@pytest.mark.parametrize("n", [0, 1, 250])
def test_hex_round_trip(n: int) -> None:
    data = _blob(n)
    assert from_hex(to_hex(data)) == data


def test_text_round_trip() -> None:
    text = "Hello bob ! How are you ?"
    assert to_text(from_text(text)) == text


# --------------------------------------------------------------------------- #
#  Ключі
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("n", [0, 1, 16, 250])
def test_random_key_has_requested_length(n: int) -> None:
    assert len(random_key(n)) == n


def test_random_key_rejects_negative_length() -> None:
    with pytest.raises(ValueError):
        random_key(-1)


def test_random_keys_do_not_repeat() -> None:
    """
    Одноразовий блокнот вимагає свіжого ключа щоразу. Збіг двох ключів по
    32 байти практично неможливий, тож повтор означав би зламаний
    генератор.
    """
    keys = {random_key(32) for _ in range(200)}
    assert len(keys) == 200
