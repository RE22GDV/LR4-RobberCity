"""
Злам «наосліп»: знайти протокол, не знаючи протоколу.

Розв'язок задачі користується тим, що умова прямо описує схему обміну.
Реальний перехоплювач такої підказки не має: він бачить три
шістнадцяткові рядки однакової довжини — і все.

Цей модуль показує, що підказка й не потрібна. Непорожніх комбінацій
трьох повідомлень усього сім; достатньо перебрати їх і запитати мовну
модель, яка з них схожа на англійський текст. Відповідь щоразу одна й та
сама, і це найкоротший шлях від «перехопленого трафіку» до «відкритого
тексту» без жодних припущень про те, як саме сторони домовлялися.

Побічний наслідок, помітний на графіку: шість хибних комбінацій дають
практично однакову (дуже погану) оцінку, а правильна відривається від
них на порядок. Тобто рішення є не лише правильним, а й упевненим.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from .analysis import plausibility, printable_ratio
from .xorcipher import xor_all

__all__ = ["Candidate", "all_combinations", "discover"]


@dataclass(frozen=True)
class Candidate:
    """Один кандидат: XOR заданої підмножини перехоплених повідомлень."""

    indices: tuple[int, ...]   #: номери повідомлень (1-based)
    data: bytes               #: результат XOR
    score: float              #: логарифмічна правдоподібність на символ
    printable: float          #: частка друкованих ASCII-байтів

    @property
    def label(self) -> str:
        """Людський запис комбінації, наприклад ``m1 xor m2 xor m3``."""
        return " xor ".join("m%d" % i for i in self.indices)

    @property
    def text(self) -> str | None:
        """Текст, якщо байти декодуються як ASCII, інакше ``None``."""
        try:
            return self.data.decode("ascii")
        except UnicodeDecodeError:
            return None


def all_combinations(messages: tuple[bytes, ...]) -> list[Candidate]:
    """
    Усі непорожні комбінації перехоплених повідомлень, оцінені мовною моделлю.

    Для трьох повідомлень це 2^3 - 1 = 7 кандидатів. Список повертається
    впорядкованим за спаданням оцінки, тож перший елемент — відповідь.
    """
    if not messages:
        raise ValueError("немає перехоплених повідомлень")
    lengths = {len(m) for m in messages}
    if len(lengths) != 1:
        raise ValueError("перехоплені повідомлення мають різну довжину")

    candidates: list[Candidate] = []
    for size in range(1, len(messages) + 1):
        for indices in combinations(range(len(messages)), size):
            data = xor_all(*(messages[i] for i in indices))
            candidates.append(Candidate(
                indices=tuple(i + 1 for i in indices),
                data=data,
                score=plausibility(data),
                printable=printable_ratio(data),
            ))
    candidates.sort(key=lambda c: -c.score)
    return candidates


def discover(messages: tuple[bytes, ...]) -> Candidate:
    """
    Найправдоподібніший кандидат — відповідь, знайдена без знання протоколу.

    Для коректного перехоплення це завжди ``m1 xor m2 xor m3``, що й
    перевіряється тестами на всіх шести офіційних прикладах.
    """
    return all_combinations(messages)[0]
