from __future__ import annotations


BASE = 19968
KEY = "beg"
CJK_MIN = 0x4E00
CJK_MAX = 0x9FA5


def encode(value: str, low_bits: int = 0) -> str:
    if not 0 <= low_bits <= 7:
        raise ValueError("Los bits inferiores deben estar entre 0 y 7")
    output: list[str] = []
    for index, character in enumerate(value):
        codepoint = BASE + ((ord(character) ^ ord(KEY[index % len(KEY)])) << 3) + low_bits
        if not CJK_MIN <= codepoint <= CJK_MAX:
            raise ValueError(f"El carácter {character!r} no cabe en el intervalo CJK de la muestra")
        output.append(chr(codepoint))
    return "".join(output)


def decode(value: str) -> str:
    return "".join(
        chr(((ord(character) - BASE) >> 3) ^ ord(KEY[index % len(KEY)]))
        for index, character in enumerate(value)
    )
