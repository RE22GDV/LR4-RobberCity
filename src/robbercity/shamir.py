"""
Та сама триетапна схема на піднесенні до степеня за модулем простого числа.

Мета модуля вужча, ніж «показати правильну реалізацію»: перевірити, чи
спрацює атака з цієї роботи, якщо «замком» зробити іншу операцію, не
змінюючи самого протоколу. Тут реалізовано варіант Шаміра над полем
лишків за простим модулем p. (Класичний варіант Мессі — Омури — це
споріднена схема над полем GF(2^n); тут вона не реалізується.)

Замість XOR «замком» слугує відображення

    E_a(x) = x^a  mod p,     D_a(y) = y^(a^-1 mod (p-1))  mod p,

де ``gcd(a, p-1) = 1``. Воно так само комутативне — ``(x^a)^b =
(x^b)^a``, — тож протокол працює буквально тими самими чотирма кроками.

Кодування повідомлення. Байти перетворюються на ціле число
``x = int.from_bytes(message, "big")``, і має виконуватися ``0 < x < p``.
Для MODP-2048 це до 255 байтів, що покриває обмеження задачі. Провідні
нульові байти при зворотному перетворенні втрачаються, тому для довільних
байтових рядків потрібне кодування з явною довжиною; для ASCII-тексту,
що не починається з нульового байта, перетворення взаємно однозначне.
Оскільки p просте і ``0 < x < p``, усі степені ``x`` ненульові за
модулем p — зокрема ``m2``, тож обернений ``m2^-1`` існує.

Що саме тут перевіряється. Перехоплені величини

    m1 = x^a,   m2 = x^(ab),   m3 = x^b

мультиплікативний аналог комбінації ``m1 xor m2 xor m3`` перетворює на
``m1 * m3 * m2^-1 = x^(a + b - ab)``, а не на ``x``. Тобто конкретна
тотожність, на якій тримається злам XOR-версії, тут не виконується.
Загальної стійкості реалізації це не доводить: аналіз інших можливих
атак виходить за межі роботи.

Застереження: навіть за правильно підібраної операції схема без
автентифікації сторін не захищає від **активного** супротивника, який
може підміняти повідомлення.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from math import gcd

__all__ = ["MODP_2048", "ShamirTranscript", "keypair", "run_shamir", "xor_style_attack"]

#: Просте число з групи MODP-2048 (RFC 3526, § 3). Безпечне просте:
#: ``p = 2q + 1``, де ``q`` також просте. Узято готове, щоб результати
#: відтворювалися, і щоб не видавати власну «саморобну» криптографію за
#: придатну до вжитку.
MODP_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)


@dataclass(frozen=True)
class ShamirTranscript:
    """Перехоплений трафік правильної версії протоколу."""

    message1: int   #: x^a      mod p
    message2: int   #: x^(ab)   mod p
    message3: int   #: x^b      mod p
    modulus: int

    @property
    def intercepted(self) -> tuple[int, int, int]:
        return (self.message1, self.message2, self.message3)


def keypair(modulus: int = MODP_2048) -> tuple[int, int]:
    """
    Випадковий показник ``a`` та обернений до нього ``a^-1 mod (p-1)``.

    Умова ``gcd(a, p-1) = 1`` потрібна, щоб обернений існував: саме він
    дозволяє власнику зняти свій «замок».
    """
    order = modulus - 1
    while True:
        a = secrets.randbelow(order - 3) + 3
        if gcd(a, order) == 1:
            return a, pow(a, -1, order)


def run_shamir(
    message: bytes,
    modulus: int = MODP_2048,
    alice: tuple[int, int] | None = None,
    bob: tuple[int, int] | None = None,
) -> ShamirTranscript:
    """
    Провести триетапний протокол Шаміра над ``message``.

    Повідомлення трактується як ціле число (big-endian) і має бути
    меншим за модуль; для MODP-2048 це до 255 байтів, що з запасом
    покриває обмеження задачі (не більше 250 символів).
    """
    x = int.from_bytes(message, "big")
    if not 0 < x < modulus:
        raise ValueError("повідомлення має бути ненульовим і коротшим за модуль")

    a, a_inv = keypair(modulus) if alice is None else alice
    b, b_inv = keypair(modulus) if bob is None else bob

    message1 = pow(x, a, modulus)            # крок 1: замок Аліси
    message2 = pow(message1, b, modulus)     # крок 2: замок Боба
    message3 = pow(message2, a_inv, modulus)  # крок 3: Аліса знімає свій

    # Крок 4: Боб знімає свій замок і має отримати вихідне число.
    if pow(message3, b_inv, modulus) != x:
        raise AssertionError("протокол не відтворив повідомлення в Боба")

    return ShamirTranscript(message1, message2, message3, modulus)


def xor_style_attack(transcript: ShamirTranscript) -> bytes:
    """
    Спроба повторити злам із цієї роботи проти варіанта на степенях.

    Мультиплікативний аналог ``m1 xor m2 xor m3`` — це ``m1 * m3 * m2^-1``.
    Для XOR така комбінація давала точно повідомлення; тут вона дає
    ``x^(a + b - ab)``, а не ``x``. Обернений ``m2^-1`` існує, бо
    ``m2 = x^(ab)`` ненульове за простим модулем.

    Повертає байти отриманого числа, щоб було видно, що це не текст.
    """
    m1, m2, m3 = transcript.intercepted
    p = transcript.modulus
    guess = (m1 * m3 % p) * pow(m2, -1, p) % p
    return guess.to_bytes((guess.bit_length() + 7) // 8 or 1, "big")
