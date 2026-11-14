"""Undo the tricks lure posts use to slip past keyword filters, before any matching.

A keyword filter is only as good as its weakest spelling. Accounts selling fake "limit
boosts" learn which words get them reported and write around them:

    styled Unicode letters    𝗙𝗨𝗟𝗜𝗭𝗔, Ｆｕｌｉｚａ          -> NFKC folds them to plain ASCII
    look-alike letters        Cyrillic "а", Greek "ο"        -> mapped to the Latin letter they imitate
    invisible characters      zero-width joiners, soft hyphens  -> removed
    spaced-out letters        F.u.l.i.z.a, M - P - E - S - A -> joined when four or more single letters
    digits and symbols        Fuliz@, M-p3sa, l0an           -> decoded, but only inside words that also
                                                                contain letters, so phone and Till
                                                                numbers are never rewritten

`variants()` returns the normalised text and, when it differs, the digit-decoded reading as
well; matching runs on both and keeps the union, so decoding can add a hit but never remove one.
`squeeze()` collapses repeated letters ("Fulizza", "Fuliiza") and is for account-name brand
checks only: applied to free text it would turn "boost" into "bost".
"""
from __future__ import annotations

import re
import unicodedata

_INVISIBLE = re.compile("[­​‌‍⁠﻿᠎]")
# Cyrillic and Greek letters that render like Latin ones in most fonts.
_HOMOGLYPHS = str.maketrans({
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t",
    "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ʟ": "l", "ᴍ": "m",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "І": "I", "Ј": "J", "Ѕ": "S",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
})
_SPACED = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ .\-_*·•|]{1,3}){3,}[A-Za-z](?![A-Za-z])")
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_MIXED = re.compile(r"[A-Za-z0-9@$!]*[A-Za-z][A-Za-z0-9@$!]*")


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    text = _INVISIBLE.sub("", text).translate(_HOMOGLYPHS)
    return _SPACED.sub(lambda m: re.sub(r"[^A-Za-z]", "", m.group(0)), text)


def _decode_token(m: re.Match) -> str:
    token = m.group(0)
    letters = sum(c.isalpha() for c in token)
    if letters < 2 or letters == len(token):
        return token                                   # a plain word, or a number with one letter in it
    return token.translate(_LEET)


def variants(text: str) -> list[str]:
    base = normalise(text)
    decoded = _MIXED.sub(_decode_token, base)
    return [base] if decoded == base else [base, decoded]


def squeeze(compact: str) -> str:
    return re.sub(r"(.)\1+", r"\1", compact)
