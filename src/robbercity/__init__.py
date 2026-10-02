"""
Лабораторна робота №4 — «Hacking at RobberCity» (CodinGame).

Злам триетапного протоколу обміну, реалізованого на XOR з одноразовими
ключами. Ключі тут бездоганні: випадкові, завдовжки з повідомлення,
використані один раз. Зламано не їх, а спосіб, у який вони застосовані.

Склад пакета:

* :mod:`robbercity.xorcipher` — XOR, одноразовий блокнот, перетворення;
* :mod:`robbercity.protocol`  — сам триетапний протокол на XOR;
* :mod:`robbercity.attack`    — атака як розв'язання системи над GF(2);
* :mod:`robbercity.discovery` — злам без знання протоколу;
* :mod:`robbercity.analysis`  — впізнавання тексту й перевірка ключів;
* :mod:`robbercity.shamir`    — та сама схема, реалізована правильно.
"""

from __future__ import annotations

from .analysis import (
    byte_entropy,
    chi_squared_uniform,
    index_of_coincidence,
    letter_ratio,
    looks_like_english,
    plausibility,
    printable_ratio,
)
from .attack import (
    MESSAGE_ROWS,
    UNKNOWNS,
    Break,
    break_transcript,
    recover_keys,
    recover_message,
    recoverable,
    span_gf2,
    subset_recovery_table,
)
from .discovery import Candidate, all_combinations, discover
from .protocol import Transcript, run_protocol, verify_transcript
from .shamir import MODP_2048, ShamirTranscript, keypair, run_shamir, xor_style_attack
from .xorcipher import (
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

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # шифр
    "xor_bytes", "xor_all", "random_key", "encrypt", "decrypt",
    "from_hex", "to_hex", "to_text", "from_text",
    # протокол
    "Transcript", "run_protocol", "verify_transcript",
    # атака
    "Break", "break_transcript", "recover_message", "recover_keys",
    "recoverable", "span_gf2", "subset_recovery_table",
    "MESSAGE_ROWS", "UNKNOWNS",
    # злам наосліп
    "Candidate", "all_combinations", "discover",
    # аналіз
    "printable_ratio", "letter_ratio", "plausibility", "looks_like_english",
    "byte_entropy", "chi_squared_uniform", "index_of_coincidence",
    # правильна реалізація
    "MODP_2048", "ShamirTranscript", "keypair", "run_shamir", "xor_style_attack",
]
