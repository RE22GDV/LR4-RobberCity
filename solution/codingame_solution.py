"""
CodinGame - "Hacking at RobberCity" (Medium)
https://www.codingame.com/training/medium/hacking-at-robbercity

Self-contained solution, submitted as-is.
This file is kept ASCII-only. The Ukrainian write-up lives in README.md
and in src/robbercity/.

Task: Alice and Bob run the "two padlocks" protocol over a XOR cipher,
each with a fresh one-time key as long as the message. We intercept all
three transmissions, given as hexadecimal strings, and must print the
plaintext.

Why it breaks. Write A for Alice's key, B for Bob's, M for the message.
The three transmissions are

    m1 = M ^ A
    m2 = m1 ^ B = M ^ A ^ B
    m3 = m2 ^ A = M ^ B

Over GF(2) these are three linear equations in the three unknowns
M, A and B, with coefficient matrix

    | 1 1 0 |
    | 1 1 1 |      determinant 1 over GF(2) -> full rank
    | 1 0 1 |

so the system is uniquely solvable, and not only for the message:

    M = m1 ^ m2 ^ m3        (A and A cancel, B and B cancel)
    A = m2 ^ m3
    B = m1 ^ m2

The one-time keys themselves are flawless. What fails is the protocol:
XOR is linear, so composing locks leaks their composition. The physical
padlock analogy does not survive the translation.

Note that two of the three transmissions are not enough: the rank drops
to two and the message stays undetermined. The break needs all three.

Time O(L), extra memory O(L), where L is the message length in bytes.
"""

import sys


def main() -> None:
    message1 = bytes.fromhex(input().strip())
    message2 = bytes.fromhex(input().strip())
    message3 = bytes.fromhex(input().strip())

    if not (len(message1) == len(message2) == len(message3)):
        print("intercepted messages have different lengths", file=sys.stderr)
        return

    plaintext = bytes(a ^ b ^ c for a, b, c in zip(message1, message2, message3))
    print(plaintext.decode("ascii"))


if __name__ == "__main__":
    main()
