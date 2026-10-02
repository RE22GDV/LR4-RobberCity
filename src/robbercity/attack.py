"""
Атака «людина посередині» на триетапний XOR-протокол.

Ключова ідея роботи: перехоплений трафік — це не три незалежні
шифротексти, а **система лінійних рівнянь над полем GF(2)**. Позначимо
невідомі ``M`` (повідомлення), ``A`` (ключ Аліси), ``B`` (ключ Боба).
Тоді кожне передане повідомлення є відомою лінійною комбінацією:

    m1 = M + A        коефіцієнти (1, 1, 0)
    m2 = M + A + B    коефіцієнти (1, 1, 1)
    m3 = M + B        коефіцієнти (1, 0, 1)

(додавання в GF(2) — це і є XOR). Матриця системи

    | 1 1 0 |
    | 1 1 1 |
    | 1 0 1 |

має над GF(2) визначник 1, тобто **повний ранг**. Отже, система
однозначно розв'язується не лише щодо ``M``, а й щодо обох ключів:

    M = m1 + m2 + m3
    A = m2 + m3
    B = m1 + m2

Саме тому злам тут повний: атакуючий дістає і текст, і обидва
одноразові блокноти. Важливо, що ці тотожності справджуються за
будь-яких A і B — зокрема за ідеально випадкових і незалежних, — тож
якість генератора ключів на атаку не впливає взагалі.

Якщо ж перехоплено лише два повідомлення з трьох, ранг системи падає до
двох, рядок ``(1, 0, 0)`` перестає належати лінійній оболонці — і
повідомлення лишається невизначеним. За моделі, у якій A і B незалежні,
рівномірно розподілені й не залежать від M, це точне твердження:
будь-яка пара перехоплень статистично незалежна від повідомлення,
тобто I(M; пара) = 0 і апріорна невизначеність M не зменшується — за
будь-якого розподілу самого M. Функція :func:`recoverable` перевіряє це
обчисленням, а не посиланням на наведену викладку.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from .protocol import Transcript
from .xorcipher import to_text, xor_all

__all__ = [
    "Break",
    "MESSAGE_ROWS",
    "UNKNOWNS",
    "recover_message",
    "recover_keys",
    "break_transcript",
    "recoverable",
    "span_gf2",
    "subset_recovery_table",
]

#: Коефіцієнти кожного переданого повідомлення у базисі (M, A, B).
#: Бітова маска: 0b100 = M, 0b010 = A, 0b001 = B.
MESSAGE_ROWS: tuple[int, int, int] = (
    0b110,  # m1 = M + A
    0b111,  # m2 = M + A + B
    0b101,  # m3 = M + B
)

#: Людські назви цільових комбінацій.
UNKNOWNS: dict[int, str] = {
    0b100: "M",
    0b010: "A",
    0b001: "B",
    0b110: "M+A",
    0b101: "M+B",
    0b011: "A+B",
    0b111: "M+A+B",
}


# --------------------------------------------------------------------------- #
#  Лінійна алгебра над GF(2) — на бітових масках
# --------------------------------------------------------------------------- #

def span_gf2(rows: tuple[int, ...]) -> frozenset[int]:
    """
    Лінійна оболонка набору рядків над GF(2).

    Рядок — це бітова маска коефіцієнтів. Оболонка будується повним
    перебором підмножин: рядків тут не більше трьох, тож це дешевше й
    прозоріше за зведення до східчастого вигляду.
    """
    reachable = {0}
    for row in rows:
        reachable |= {value ^ row for value in reachable}
    return frozenset(reachable)


def recoverable(observed: tuple[int, ...], target: int) -> bool:
    """
    Чи відновлюється комбінація ``target`` із перехоплених рядків?

    Відновлюється тоді й лише тоді, коли ``target`` належить лінійній
    оболонці спостережених рядків: саме тоді існує підмножина
    перехоплених повідомлень, XOR якої дорівнює шуканій величині.
    """
    return target in span_gf2(observed)


def subset_recovery_table() -> list[dict]:
    """
    Що дає перехоплення кожної підмножини повідомлень.

    Повертає рядки таблиці для звіту: для всіх 7 непорожніх підмножин —
    ранг системи та перелік величин, які з неї відновлюються. Результат
    обчислюється, а не виписується вручну.
    """
    table = []
    for size in (1, 2, 3):
        for indices in combinations((0, 1, 2), size):
            rows = tuple(MESSAGE_ROWS[i] for i in indices)
            reach = span_gf2(rows)
            # Ранг = log2 розміру оболонки (оболонка — лінійний підпростір).
            rank = max(0, len(reach).bit_length() - 1)
            found = [name for mask, name in sorted(UNKNOWNS.items())
                     if mask in reach]
            table.append({
                "messages": [i + 1 for i in indices],
                "rank": rank,
                "message_recoverable": 0b100 in reach,
                "recovered": found,
            })
    return table


# --------------------------------------------------------------------------- #
#  Власне атака
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Break:
    """Результат зламу: усе, що атакуючий дістає з трьох повідомлень."""

    message: bytes       #: відкритий текст
    alice_key: bytes     #: одноразовий ключ Аліси
    bob_key: bytes       #: одноразовий ключ Боба

    @property
    def text(self) -> str:
        """Відкритий текст у кодуванні ASCII — те, що друкує розв'язок."""
        return to_text(self.message)


def recover_message(message1: bytes, message2: bytes, message3: bytes) -> bytes:
    """
    Відновити відкритий текст: ``M = m1 + m2 + m3`` над GF(2).

    Розгорнуто::

        (M+A) + (M+A+B) + (M+B) = M + (A+A) + (B+B) = M

    Жодного перебору, жодних припущень про мову тексту — лише
    властивості XOR.
    """
    return xor_all(message1, message2, message3)


def recover_keys(
    message1: bytes, message2: bytes, message3: bytes
) -> tuple[bytes, bytes]:
    """
    Відновити обидва одноразові ключі: ``A = m2 + m3``, ``B = m1 + m2``.

    Це наслідок повного рангу системи. Практично він важливіший за сам
    текст: знаючи ключі, атакуючий може не лише читати, а й підміняти
    повідомлення, лишаючись непоміченим.
    """
    alice_key = xor_all(message2, message3)   # (M+A+B) + (M+B) = A
    bob_key = xor_all(message1, message2)     # (M+A) + (M+A+B) = B
    return alice_key, bob_key


def break_transcript(transcript: Transcript | tuple[bytes, bytes, bytes]) -> Break:
    """Повний злам перехопленого сеансу."""
    if isinstance(transcript, Transcript):
        m1, m2, m3 = transcript.intercepted
    else:
        m1, m2, m3 = transcript
    if not (len(m1) == len(m2) == len(m3)):
        raise ValueError("перехоплені повідомлення мають різну довжину")
    alice_key, bob_key = recover_keys(m1, m2, m3)
    return Break(
        message=recover_message(m1, m2, m3),
        alice_key=alice_key,
        bob_key=bob_key,
    )
