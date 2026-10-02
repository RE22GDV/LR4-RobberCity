"""
Триетапний протокол «без обміну ключами», реалізований на XOR.

Ідея взята з класичної загадки про посилку та два замки:

    1. Аліса замикає посилку своїм замком і надсилає Бобу.
    2. Боб вішає свій замок і повертає посилку Алісі.
    3. Аліса знімає свій замок і надсилає посилку Бобу.
    4. Боб знімає свій замок і відкриває посилку.

Жоден ключ не передається каналом — і саме це робить схему
привабливою. У криптографії вона відома як триетапний протокол Шаміра
(Shamir three-pass protocol). Протокол сам собою коректний; питання
лише в тому, яким шифром реалізувати «замок».

Цей модуль реалізує саме ту (хибну) версію, що описана в умові задачі:
замком слугує XOR з одноразовим ключем. Модуль :mod:`robbercity.shamir`
реалізує ту саму схему правильно — на піднесенні до степеня в скінченному
полі, — щоб показати, що зламано саме реалізацію, а не ідею.
"""

from __future__ import annotations

from dataclasses import dataclass

from .xorcipher import encrypt, random_key, to_hex, xor_bytes

__all__ = ["Transcript", "run_protocol", "verify_transcript"]


@dataclass(frozen=True)
class Transcript:
    """
    Усе, що бачить сторонній спостерігач каналу: три повідомлення.

    Поля ``alice_key``, ``bob_key`` і ``message`` зберігаються лише для
    перевірок у тестах і експериментах — атака ними не користується.
    """

    message1: bytes          #: M xor A      (Аліса -> Боб)
    message2: bytes          #: M xor A xor B (Боб -> Аліса)
    message3: bytes          #: M xor B      (Аліса -> Боб)

    message: bytes = b""     #: справжній відкритий текст (недоступний атакуючому)
    alice_key: bytes = b""   #: ключ Аліси   (недоступний атакуючому)
    bob_key: bytes = b""     #: ключ Боба    (недоступний атакуючому)

    @property
    def intercepted(self) -> tuple[bytes, bytes, bytes]:
        """Рівно те, що доступне атакуючому."""
        return (self.message1, self.message2, self.message3)

    def as_hex_lines(self) -> list[str]:
        """Три рядки шістнадцяткових цифр — формат входу задачі."""
        return [to_hex(m) for m in self.intercepted]

    def __len__(self) -> int:
        return len(self.message1)


def run_protocol(
    message: bytes,
    alice_key: bytes | None = None,
    bob_key: bytes | None = None,
) -> Transcript:
    """
    Провести повний сеанс і повернути перехоплений трафік.

    Якщо ключі не задані, обидва генеруються випадково й мають довжину
    повідомлення — тобто є повноцінними одноразовими блокнотами.

    Відповідність крокам загадки:

    ========  ===================================  =========================
    Крок      Дія                                  Що йде каналом
    ========  ===================================  =========================
    1         Аліса накладає свій ключ             ``m1 = M xor A``
    2         Боб накладає свій ключ               ``m2 = m1 xor B``
    3         Аліса знімає свій ключ               ``m3 = m2 xor A``
    4         Боб знімає свій ключ і читає текст   --
    ========  ===================================  =========================

    Крок 4 каналом не передається, тому атакуючий його не бачить; саме
    тому в задачі три повідомлення, а не чотири.
    """
    n = len(message)
    alice_key = random_key(n) if alice_key is None else alice_key
    bob_key = random_key(n) if bob_key is None else bob_key
    if len(alice_key) != n or len(bob_key) != n:
        raise ValueError("ключі мають бути завдовжки з повідомлення")

    message1 = encrypt(message, alice_key)      # M xor A
    message2 = encrypt(message1, bob_key)       # M xor A xor B
    message3 = encrypt(message2, alice_key)     # M xor B

    # Крок 4: Боб знімає свій ключ і має отримати вихідний текст.
    # Це внутрішня перевірка коректності самого протоколу.
    recovered_by_bob = encrypt(message3, bob_key)
    if recovered_by_bob != message:
        raise AssertionError("протокол не відтворив повідомлення в Боба")

    return Transcript(
        message1=message1,
        message2=message2,
        message3=message3,
        message=message,
        alice_key=alice_key,
        bob_key=bob_key,
    )


def verify_transcript(transcript: Transcript) -> bool:
    """
    Перевірити, що перехоплення справді відповідає протоколу.

    Корисно як незалежна перевірка: ми не просто довіряємо генератору,
    а щоразу переконуємося, що ``m2 = m1 xor B`` і ``m3 = m2 xor A``.
    """
    if not transcript.alice_key or not transcript.bob_key:
        raise ValueError("для перевірки потрібні ключі обох сторін")
    expected2 = xor_bytes(transcript.message1, transcript.bob_key)
    expected3 = xor_bytes(transcript.message2, transcript.alice_key)
    return transcript.message2 == expected2 and transcript.message3 == expected3
