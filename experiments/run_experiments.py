"""
Обчислювальні експерименти лабораторної роботи.

    python experiments/run_experiments.py            # усі експерименти
    python experiments/run_experiments.py --quick    # скорочений прогін

Результати:
    docs/results/experiments.json   — усі виміряні величини
    docs/results/summary.md         — зведена таблиця для звіту
    docs/figures/*.png              — рисунки (+ pdf/ — версії без заголовків)

Усі генератори випадкових чисел ініціалізуються фіксованим зерном,
тому результати відтворювані.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import PercentFormatter  # noqa: E402

from robbercity import (  # noqa: E402
    MESSAGE_ROWS,
    all_combinations,
    break_transcript,
    byte_entropy,
    chi_squared_uniform,
    from_hex,
    index_of_coincidence,
    letter_ratio,
    looks_like_english,
    plausibility,
    printable_ratio,
    random_key,
    recoverable,
    run_protocol,
    run_shamir,
    span_gf2,
    subset_recovery_table,
    xor_bytes,
    xor_style_attack,
)
from robbercity.analysis import MIN_LETTER_RATIO, MIN_PLAUSIBILITY  # noqa: E402

# --------------------------------------------------------------------------- #
#  Оформлення рисунків
#  Палітра — перші три категорійні слоти референсної системи (blue/orange/aqua):
#  саме ця трійка проходить перевірку all-pairs за колірним зором.
# --------------------------------------------------------------------------- #

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e3e2de"
S1 = "#2a78d6"   # слот 1 — синій
S2 = "#eb6834"   # слот 2 — помаранчевий
S3 = "#1baf7a"   # слот 3 — бірюзовий

plt.rcParams.update({
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK_2,
    "axes.titlecolor": INK,
    "axes.titlesize": 12,
    "axes.titleweight": "semibold",
    "axes.labelsize": 9.5,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "xtick.color": INK_2,
    "ytick.color": INK_2,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.frameon": False,
    "legend.fontsize": 9,
    "lines.linewidth": 2.0,
    "font.size": 10,
})

FIG = ROOT / "docs" / "figures"
RES = ROOT / "docs" / "results"
CASES = json.loads(
    (ROOT / "tests" / "official_cases.json").read_text(encoding="utf-8")
)["cases"]


def _n(value: float, digits: int = 2) -> str:
    """Число з комою як десятковим роздільником (для підписів на рисунках)."""
    return ("%.*f" % (digits, value)).replace(".", ",")


def _finish(ax, note: str | None = None) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    if note:
        ax.text(0.995, -0.17, note, transform=ax.transAxes, ha="right", va="top",
                fontsize=7.5, color=INK_2)


def save(fig, name: str) -> str:
    """
    Зберігає рисунок двічі:
      docs/figures/<name>      — із заголовком, для README на GitHub;
      docs/figures/pdf/<name>  — без заголовка, для звіту, де роль заголовка
                                 виконує підпис «Рисунок N.M – ...».
    """
    FIG.mkdir(parents=True, exist_ok=True)
    path = FIG / name
    fig.savefig(path, dpi=200, bbox_inches="tight")

    (FIG / "pdf").mkdir(parents=True, exist_ok=True)
    for ax in fig.axes:
        ax.set_title("")
    if fig._suptitle is not None:
        fig.suptitle("")
    fig.savefig(FIG / "pdf" / name, dpi=200, bbox_inches="tight")

    plt.close(fig)
    print("    рисунок -> %s (+ pdf/)" % path.relative_to(ROOT))
    return str(path.relative_to(ROOT)).replace("\\", "/")


def seeded_protocol(rng: random.Random, message: bytes):
    """
    Сеанс протоколу з ключами від генератора із зерном.

    Бібліотечна run_protocol бере ключі з модуля secrets, на який зерно
    не впливає. Для експериментів потрібна відтворюваність, тож ключі
    тут генеруються з rng; на сам протокол і атаку це не впливає.
    """
    n = len(message)
    return run_protocol(message, rng.randbytes(n), rng.randbytes(n))


def english_text(rng: random.Random, length: int) -> bytes:
    """Фрагмент англійського тексту заданої довжини — для контрольних вимірів."""
    source = (
        "the quick brown fox jumps over the lazy dog while the postmen of "
        "robber city open every parcel they carry and alice keeps writing "
        "letters to bob about locks keys and parcels that never arrive "
    ) * 6
    start = rng.randrange(len(source) - length - 1)
    return source[start:start + length].encode("ascii")


# --------------------------------------------------------------------------- #
#  Експеримент 1 — що саме йде каналом
# --------------------------------------------------------------------------- #

def exp_channel(rng: random.Random) -> dict:
    """
    Окреме перехоплення не зберігає статистики відкритого тексту.

    За незалежного рівномірного ключа m1 = M xor A розподілене рівномірно
    й не залежить від M — це точна властивість одноразового блокнота.
    Вимірювання лише ілюструє її на одному прикладі. Беремо найгірший для шифру випадок — текст із нульовою ентропією
    (сама літера «A») — і дивимося, що з ним робить одноразовий ключ.
    Якби хоч одне з трьох повідомлень зберігало статистику відкритого
    тексту, злам був би тривіальним і без протоколу.
    """
    print("[1] Що саме видно в каналі")
    text = b"A" * 240
    transcript = seeded_protocol(rng, text)
    reference = rng.randbytes(240)

    rows = [
        ("відкритий текст", text),
        ("m1 = M xor A", transcript.message1),
        ("m2 = m1 xor B", transcript.message2),
        ("m3 = m2 xor A", transcript.message3),
        ("еталон: випадкові байти", reference),
    ]
    stats = [{
        "label": label,
        "entropy": byte_entropy(data),
        "ioc": index_of_coincidence(data),
        "printable": printable_ratio(data),
    } for label, data in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.2, 3.9))
    labels = [s["label"] for s in stats]
    colors = [S2] + [S1] * 3 + [INK_2]

    ax1.barh(range(len(stats)), [s["entropy"] for s in stats], color=colors, zorder=3)
    ax1.set_yticks(range(len(stats)), labels)
    ax1.invert_yaxis()
    ax1.set_xlabel("ентропія, біт/байт")
    ax1.set_xlim(0, 8.4)
    ax1.axvline(8, color=INK_2, linestyle=":", linewidth=1.2)
    ax1.text(8, len(stats) - 0.3, "8 біт — межа лише\nдля довгої вибірки",
             ha="right", va="top", fontsize=7.5, color=INK_2)
    _finish(ax1, "еталон — випадкові байти такої самої довжини, а не число 8")

    ax2.barh(range(len(stats)), [100 * s["printable"] for s in stats],
             color=colors, zorder=3)
    ax2.set_yticks(range(len(stats)), ["" for _ in stats])
    ax2.invert_yaxis()
    ax2.set_xlabel("частка друкованих ASCII-байтів")
    ax2.xaxis.set_major_formatter(PercentFormatter())
    ax2.set_xlim(0, 108)
    _finish(ax2)

    fig.suptitle("Рис. 1. Окреме перехоплення не зберігає статистики тексту",
                 fontsize=12, fontweight="semibold", color=INK)
    fig.tight_layout()
    path = save(fig, "fig1_channel.png")

    for s in stats:
        print("    %-26s ентропія %.3f  друковані %5.1f %%"
              % (s["label"], s["entropy"], 100 * s["printable"]))
    return {"figure": path, "length": len(text), "stats": stats}


# --------------------------------------------------------------------------- #
#  Експеримент 2 — скільки перехоплень потрібно
# --------------------------------------------------------------------------- #

def exp_how_many(rng: random.Random, quick: bool) -> dict:
    """
    Два перехоплення не дають нічого, три — дають усе.

    Теорія (ранг системи над GF(2)) перевіряється прямим вимірюванням:
    для кожної підмножини пробуємо відновити текст і рахуємо частку
    успіхів. Для пар вона має бути нульовою не «майже завжди», а завжди.
    """
    print("[2] Скільки перехоплень потрібно")
    trials = 2000 if not quick else 200
    length = 48
    subsets = [(0,), (0, 1), (0, 2), (1, 2), (0, 1, 2)]
    success = {s: 0 for s in subsets}

    for _ in range(trials):
        text = english_text(rng, length)
        t = seeded_protocol(rng, text)
        sent = t.intercepted
        for subset in subsets:
            # Найкраще, що можна зробити з підмножини, — XOR усіх її
            # елементів: будь-яка інша комбінація є XOR-ом підмножини.
            guess = sent[subset[0]]
            for i in subset[1:]:
                guess = xor_bytes(guess, sent[i])
            success[subset] += (guess == text)

    table = subset_recovery_table()
    labels = [", ".join("m%d" % (i + 1) for i in s) for s in subsets]
    values = [100.0 * success[s] / trials for s in subsets]
    # Частка апріорної невизначеності M, що лишається після перехоплення.
    # За незалежних рівномірних ключів підмножина, з якої M не
    # відновлюється, статистично незалежна від M, тож невизначеність не
    # зменшується зовсім (100 %); інакше вона зникає (0 %). Це справджується
    # за будь-якого розподілу M. Число 8L біт — лише окремий випадок для
    # повідомлення, рівномірно вибраного з усіх 2^(8L) рядків.
    remaining = [0.0 if recoverable(tuple(MESSAGE_ROWS[i] for i in s), 0b100)
                 else 100.0 for s in subsets]
    uniform_bits = [8.0 * length * r / 100.0 for r in remaining]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.4, 4.0))
    x = range(len(subsets))
    colors = [S1 if v else INK_2 for v in values]

    bars = ax1.bar(x, values, color=colors, width=0.62, zorder=3)
    ax1.set_xticks(list(x), labels, rotation=18, ha="right")
    ax1.set_ylabel("частка відновлених повідомлень")
    ax1.yaxis.set_major_formatter(PercentFormatter())
    ax1.set_ylim(0, 118)
    for rect, value in zip(bars, values):
        ax1.annotate("%s %%" % _n(value, 0),
                     xy=(rect.get_x() + rect.get_width() / 2, value),
                     xytext=(0, 4), textcoords="offset points",
                     ha="center", fontsize=9, color=INK)
    _finish(ax1)

    ax2.bar(x, remaining, color=[INK_2 if r else S1 for r in remaining],
            width=0.62, zorder=3)
    ax2.set_xticks(list(x), labels, rotation=18, ha="right")
    ax2.set_ylabel("лишається невизначеності M")
    ax2.yaxis.set_major_formatter(PercentFormatter())
    ax2.set_ylim(0, 118)
    for xi, r in zip(x, remaining):
        ax2.annotate("%s %%" % _n(r, 0), xy=(xi, r), xytext=(0, 4),
                     textcoords="offset points", ha="center",
                     fontsize=9, color=INK)
    _finish(ax2)

    fig.suptitle("Рис. 2. Повідомлення відновлюється лише з усіх трьох перехоплень",
                 fontsize=12, fontweight="semibold", color=INK)
    fig.text(0.995, -0.03, "ліворуч — %d сеансів на стовпчик, повідомлення по %d "
             "байтів; праворуч — модель із незалежними рівномірними ключами"
             % (trials, length), ha="right", fontsize=7.5, color=INK_2)
    fig.tight_layout()
    path = save(fig, "fig2_how_many.png")

    for subset, label in zip(subsets, labels):
        print("    %-12s відновлено %6.2f %%  ранг %d"
              % (label, 100.0 * success[subset] / trials,
                 max(0, len(span_gf2(tuple(MESSAGE_ROWS[i] for i in subset))).bit_length() - 1)))
    return {
        "figure": path,
        "trials": trials,
        "length": length,
        "success_percent": {label: 100.0 * success[s] / trials
                            for s, label in zip(subsets, labels)},
        "remaining_percent": {label: r for label, r in zip(labels, remaining)},
        "residual_bits_uniform_message": {label: u for label, u in zip(labels, uniform_bits)},
        "recovery_table": table,
    }


# --------------------------------------------------------------------------- #
#  Експеримент 3 — злам без знання протоколу
# --------------------------------------------------------------------------- #

def exp_blind() -> dict:
    """
    Чи потрібна атакуючому підказка з умови?

    Перебираємо всі сім непорожніх комбінацій трьох повідомлень і
    оцінюємо кожну мовною моделлю. Якщо правильна щоразу виграє з
    відривом, знання протоколу не потрібне взагалі.
    """
    print("[3] Злам без знання протоколу")
    per_case = []
    for case in CASES:
        messages = tuple(from_hex(h) for h in case["messages"])
        ranked = all_combinations(messages)
        per_case.append({
            "label": case["label"],
            "winner": ranked[0].label,
            "correct": ranked[0].indices == (1, 2, 3),
            "scores": {c.label: c.score for c in ranked},
            "margin": ranked[0].score - ranked[1].score,
        })
        print("    %-32s переможець %-22s відрив %6.1f"
              % (case["label"], ranked[0].label, per_case[-1]["margin"]))

    order = [c.label for c in sorted(
        all_combinations(tuple(from_hex(h) for h in CASES[0]["messages"])),
        key=lambda c: (len(c.indices), c.indices))]
    means = [statistics.mean(p["scores"][lbl] for p in per_case) for lbl in order]

    # Горизонтальні смуги: підписи комбінацій довгі, а при повороті вони
    # налазили на заголовок і на примітку.
    pairs = sorted(zip(order, means), key=lambda kv: kv[1])
    names = [k for k, _ in pairs]
    vals = [v for _, v in pairs]
    colors = [S2 if name.count("xor") == 2 else S1 for name in names]

    fig, ax = plt.subplots(figsize=(9.4, 4.2))
    bars = ax.barh(range(len(names)), vals, color=colors, height=0.62, zorder=3)
    ax.set_yticks(range(len(names)), names)
    ax.set_xlabel("оцінка мовної моделі (середня за 6 тестами); більше — краще")
    ax.set_xlim(min(vals) * 1.12, 8)
    for rect, value in zip(bars, vals):
        ax.annotate(_n(value, 1), xy=(value, rect.get_y() + rect.get_height() / 2),
                    xytext=(6 if value > -5 else -6, 0), textcoords="offset points",
                    va="center", ha="left" if value > -5 else "right",
                    fontsize=8.5, color=INK)
    ax.annotate("єдиний осмислений текст",
                xy=(vals[-1], len(names) - 1), xytext=(-26, 0),
                textcoords="offset points", ha="right", fontsize=9, color=INK,
                arrowprops=dict(arrowstyle="->", color=S2, linewidth=1.4))
    ax.set_title("Рис. 3. Правильну комбінацію видно без жодної підказки")
    _finish(ax, "усі 7 непорожніх комбінацій трьох перехоплених повідомлень")
    path = save(fig, "fig3_blind.png")

    margins = [p["margin"] for p in per_case]
    return {
        "figure": path,
        "per_case": per_case,
        "all_correct": all(p["correct"] for p in per_case),
        "mean_scores": dict(zip(order, means)),
        "min_margin": min(margins),
        "mean_margin": statistics.mean(margins),
    }


# --------------------------------------------------------------------------- #
#  Експеримент 4 — надійність розпізнавача тексту
# --------------------------------------------------------------------------- #

def exp_detector(rng: random.Random, quick: bool) -> dict:
    """
    Дві слабкі ознаки дають одну надійну.

    Найскладніший супротивник для розпізнавача — не випадкові байти, а
    випадкові *друковані* символи: вони вже проходять першу умову.
    Міряємо частоту хибних спрацювань кожного критерію окремо та їх
    кон'юнкції.
    """
    print("[4] Надійність розпізнавача тексту")
    trials = 20000 if not quick else 2000
    length = 60

    counters = {"letters": 0, "quadgrams": 0, "both": 0}
    for _ in range(trials):
        data = bytes(rng.randrange(0x20, 0x7F) for _ in range(length))
        by_letters = letter_ratio(data) >= MIN_LETTER_RATIO
        by_score = plausibility(data) > MIN_PLAUSIBILITY
        counters["letters"] += by_letters
        counters["quadgrams"] += by_score
        counters["both"] += by_letters and by_score

    real_detected = sum(looks_like_english(c["expected"].encode("ascii"))
                        for c in CASES)
    random_bytes_fp = sum(
        looks_like_english(bytes(rng.randrange(256) for _ in range(length)))
        for _ in range(trials)
    )

    labels = ["лише частка\nлітер", "лише\nквадриграми", "обидві умови\nразом"]
    values = [100.0 * counters[k] / trials for k in ("letters", "quadgrams", "both")]

    fig, ax = plt.subplots(figsize=(8.4, 4.0))
    bars = ax.bar(range(3), values, color=[S1, S1, S3], width=0.55, zorder=3)
    ax.set_xticks(range(3), labels)
    ax.set_ylabel("частка хибних спрацювань")
    ax.yaxis.set_major_formatter(PercentFormatter())
    ax.set_ylim(0, max(values) * 1.25 + 0.5)
    for rect, value in zip(bars, values):
        ax.annotate("%s %%" % _n(value, 2),
                    xy=(rect.get_x() + rect.get_width() / 2, value),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", fontsize=9.5, color=INK)
    ax.set_title("Рис. 4. Поодинці критерії помиляються, разом — ні")
    _finish(ax, "%d випадкових ДРУКОВАНИХ рядків по %d символів"
            % (trials, length))
    path = save(fig, "fig4_detector.png")

    for key, value in zip(("letters", "quadgrams", "both"), values):
        print("    %-12s хибних спрацювань %6.3f %%" % (key, value))
    return {
        "figure": path,
        "trials": trials,
        "length": length,
        "false_positive_percent": {
            "letters_only": values[0],
            "quadgrams_only": values[1],
            "both": values[2],
        },
        "random_bytes_false_positives": random_bytes_fp,
        "real_texts_detected": real_detected,
        "real_texts_total": len(CASES),
        "thresholds": {"letter_ratio": MIN_LETTER_RATIO,
                       "plausibility": MIN_PLAUSIBILITY},
    }


# --------------------------------------------------------------------------- #
#  Експеримент 5 — чи винні ключі
# --------------------------------------------------------------------------- #

def exp_keys_are_fine(rng: random.Random, quick: bool) -> dict:
    """
    Допоміжна перевірка: чи схожі відновлені ключі на випадкові.

    Відновлені з офіційних тестів ключі порівнюються з трьома еталонами:
    справді випадковими байтами, англійським текстом і повторюваним
    ключем (типова помилка «блокнот використали двічі»). Дві метрики на
    дванадцяти коротких ключах можуть показати лише схожість за цими
    метриками, а не довести випадковість. Головний аргумент інший:
    формули атаки справджуються за будь-яких ключів, зокрема ідеальних.
    """
    print("[5] Чи винні ключі")
    trials = 400 if not quick else 60

    recovered = []
    for case in CASES:
        result = break_transcript(tuple(from_hex(h) for h in case["messages"]))
        recovered.extend([result.alice_key, result.bob_key])

    def describe(samples: list[bytes]) -> dict:
        return {
            "entropy": statistics.mean(byte_entropy(s) for s in samples),
            "ioc": statistics.mean(index_of_coincidence(s) for s in samples),
            "chi2": statistics.mean(chi_squared_uniform(s) for s in samples),
            "count": len(samples),
            "mean_length": statistics.mean(len(s) for s in samples),
        }

    lengths = [len(s) for s in recovered]
    reference = [rng.randbytes(rng.choice(lengths)) for _ in range(trials)]
    english = [english_text(rng, rng.choice(lengths)) for _ in range(trials)]
    repeated = [bytes([rng.randrange(256)] * rng.choice(lengths))
                for _ in range(trials)]

    groups = {
        "відновлені ключі": describe(recovered),
        "випадкові байти": describe(reference),
        "англійський текст": describe(english),
        "повторюваний байт": describe(repeated),
    }

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.4, 4.0))
    names = list(groups)
    colors = [S2, S1, S3, INK_2]

    ax1.bar(range(len(names)), [groups[n]["entropy"] for n in names],
            color=colors, width=0.58, zorder=3)
    ax1.set_xticks(range(len(names)), ["відновлені\nключі", "випадкові\nбайти",
                                       "англійський\nтекст", "повторюваний\nбайт"])
    ax1.set_ylabel("ентропія, біт/байт")
    ax1.set_ylim(0, 8.6)
    ax1.axhline(8, color=INK_2, linestyle=":", linewidth=1.2)
    ax1.text(3.45, 8, "8 біт", ha="right", va="bottom", fontsize=7.5, color=INK_2)
    _finish(ax1, "ключі короткі, тому еталоном є не 8, а випадкові байти "
                 "такої самої довжини")

    ax2.bar(range(len(names)), [groups[n]["ioc"] for n in names],
            color=colors, width=0.58, zorder=3)
    ax2.set_xticks(range(len(names)), ["відновлені\nключі", "випадкові\nбайти",
                                       "англійський\nтекст", "повторюваний\nбайт"])
    ax2.set_ylabel("індекс відповідності")
    ax2.set_yscale("log")
    _finish(ax2)

    fig.suptitle("Рис. 5. За використаними метриками ключі схожі на випадкові",
                 fontsize=12, fontweight="semibold", color=INK)
    fig.tight_layout()
    path = save(fig, "fig5_keys.png")

    for name, stats in groups.items():
        print("    %-20s ентропія %.3f  IoC %.5f" % (name, stats["entropy"], stats["ioc"]))
    return {"figure": path, "groups": groups, "trials": trials,
            "recovered_keys": len(recovered)}


# --------------------------------------------------------------------------- #
#  Експеримент 6 — та сама схема на піднесенні до степеня
# --------------------------------------------------------------------------- #

def exp_shamir(rng: random.Random, quick: bool) -> dict:
    """
    Чи спрацює та сама атака проти іншої операції.

    Той самий чотирикроковий обмін, але «замком» слугує піднесення до
    степеня за модулем простого числа. Атака з цієї роботи повторюється
    буквально — і не спрацьовує жодного разу.
    """
    print("[6] Та сама схема на піднесенні до степеня")
    trials = 200 if not quick else 25

    xor_hits = 0
    shamir_hits = 0
    xor_time = 0.0
    shamir_time = 0.0

    for _ in range(trials):
        text = english_text(rng, 48)

        t0 = time.perf_counter()
        transcript = seeded_protocol(rng, text)
        xor_hits += break_transcript(transcript).message == text
        xor_time += time.perf_counter() - t0

        t0 = time.perf_counter()
        shamir = run_shamir(text)
        shamir_hits += xor_style_attack(shamir) == text
        shamir_time += time.perf_counter() - t0

    labels = ["XOR\n(реалізація з умови)", "піднесення до степеня\n(MODP-2048)"]
    values = [100.0 * xor_hits / trials, 100.0 * shamir_hits / trials]

    fig, ax = plt.subplots(figsize=(8.0, 4.0))
    bars = ax.bar(range(2), values, color=[S2, S3], width=0.5, zorder=3)
    ax.set_xticks(range(2), labels)
    ax.set_ylabel("частка успішних зламів тією самою атакою")
    ax.yaxis.set_major_formatter(PercentFormatter())
    ax.set_ylim(0, 115)
    for rect, value in zip(bars, values):
        ax.annotate("%s %%" % _n(value, 0),
                    xy=(rect.get_x() + rect.get_width() / 2, value),
                    xytext=(0, 5), textcoords="offset points",
                    ha="center", fontsize=11, color=INK)
    ax.set_title("Рис. 6. Розглянута атака не спрацювала проти варіанта на степенях")
    _finish(ax, "по %d сеансів; обидва протоколи — чотирикрокові, "
                "відмінність лише в операції" % trials)
    path = save(fig, "fig6_shamir.png")

    print("    XOR:     зламано %d з %d (%.3f мс на сеанс)"
          % (xor_hits, trials, 1000 * xor_time / trials))
    print("    Шамір:   зламано %d з %d (%.1f мс на сеанс)"
          % (shamir_hits, trials, 1000 * shamir_time / trials))
    return {
        "figure": path,
        "trials": trials,
        "xor_success_percent": values[0],
        "shamir_success_percent": values[1],
        "xor_ms_per_session": 1000 * xor_time / trials,
        "shamir_ms_per_session": 1000 * shamir_time / trials,
        "modulus_bits": 2048,
    }


# --------------------------------------------------------------------------- #

def write_summary(results: dict) -> None:
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "experiments.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    how = results["how_many"]
    det = results["detector"]
    keys = results["keys"]
    lines = [
        "# Зведені результати експериментів",
        "",
        "Згенеровано автоматично: `python experiments/run_experiments.py`",
        "",
        "## Що дає кожна підмножина перехоплень",
        "",
        "| Перехоплено | Ранг системи над GF(2) | Відновлено повідомлень | Лишається апріорної невизначеності M |",
        "|---|---:|---:|---:|",
    ]
    ranks = {", ".join("m%d" % i for i in row["messages"]): row["rank"]
             for row in how["recovery_table"]}
    for label, percent in how["success_percent"].items():
        lines.append("| %s | %d | %.1f %% | %.0f %% |"
                     % (label, ranks[label], percent, how["remaining_percent"][label]))
    lines += [
        "",
        "По %d випробувань на рядок, повідомлення по %d байтів."
        % (how["trials"], how["length"]),
        "",
        "## Розпізнавач тексту: хибні спрацювання",
        "",
        "| Критерій | Хибних спрацювань |",
        "|---|---:|",
        "| лише частка літер | %.2f %% |" % det["false_positive_percent"]["letters_only"],
        "| лише квадриграми | %.2f %% |" % det["false_positive_percent"]["quadgrams_only"],
        "| обидві умови разом | %.3f %% |" % det["false_positive_percent"]["both"],
        "",
        "%d випадкових друкованих рядків по %d символів; справжні тексти "
        "розпізнано %d з %d."
        % (det["trials"], det["length"], det["real_texts_detected"],
           det["real_texts_total"]),
        "",
        "## Статистика відновлених ключів",
        "",
        "| Набір | Ентропія, біт/байт | Індекс відповідності |",
        "|---|---:|---:|",
    ]
    for name, stats in keys["groups"].items():
        lines.append("| %s | %.3f | %.5f |" % (name, stats["entropy"], stats["ioc"]))
    lines += [
        "",
        "## Та сама схема з іншим «замком»",
        "",
        "| Реалізація замка | Успішність атаки |",
        "|---|---:|",
        "| XOR (з умови задачі) | %.0f %% |" % results["shamir"]["xor_success_percent"],
        "| піднесення до степеня, MODP-2048 | %.0f %% |"
        % results["shamir"]["shamir_success_percent"],
        "",
    ]
    (RES / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n    зведення -> docs/results/summary.md")
    print("    сирі дані -> docs/results/experiments.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="скорочений прогін")
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    t0 = time.perf_counter()
    seeds = {"channel": 20261002, "how_many": 4242, "detector": 31337,
             "keys": 777, "shamir": 99}
    print("Офіційних тестів у наборі: %d\n" % len(CASES))

    results = {
        "meta": {
            "official_cases": len(CASES),
            "seeds": seeds,
            "quick": args.quick,
        },
        "channel": exp_channel(random.Random(seeds["channel"])),
        "how_many": exp_how_many(random.Random(seeds["how_many"]), args.quick),
        "blind": exp_blind(),
        "detector": exp_detector(random.Random(seeds["detector"]), args.quick),
        "keys": exp_keys_are_fine(random.Random(seeds["keys"]), args.quick),
        "shamir": exp_shamir(random.Random(seeds["shamir"]), args.quick),
    }
    results["meta"]["total_seconds"] = time.perf_counter() - t0
    write_summary(results)
    print("\nГотово за %.1f с" % results["meta"]["total_seconds"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
