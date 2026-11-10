# -*- coding: utf-8 -*-
"""Steganografie LSB - Laboratorul 6, Lucrarea B (B5-B6).

Ascunde un mesaj in cel mai putin semnificativ bit (LSB) al fiecarui octet de
culoare (R, G, B, R, G, B, ...) dintr-o imagine. Mesajul se termina cu un octet 0.
Se salveaza obligatoriu in PNG (fara pierderi): JPEG recomprima imaginea si
distruge bitii ascunsi.

    python stego.py                      # demo: ascunde + dezvaluie + verificare
    python stego.py ascunde probe/foto.jpg "FLAG{...}" stego.png
    python stego.py dezvaluie stego.png
"""

import os
import sys

from PIL import Image

RADACINA = os.path.dirname(os.path.abspath(__file__))
MESAJ = b"FLAG{ascuns_in_pixeli}"


# --------------------------------------------------------------------- B5
def ascunde(sursa, mesaj, iesire):
    """Scrie `mesaj` (bytes) in LSB-ul pixelilor lui `sursa`, salveaza in `iesire` (PNG)."""
    img = Image.open(sursa).convert("RGB")
    date = bytearray(img.tobytes())          # R,G,B,R,G,B,... cate un octet pe canal
    biti = "".join(f"{x:08b}" for x in mesaj + b"\x00")   # \x00 = final de mesaj
    if len(biti) > len(date):
        raise ValueError(f"mesaj prea lung: {len(biti)} biti, capacitate {len(date)}")
    for i, bit in enumerate(biti):
        date[i] = (date[i] & ~1) | int(bit)  # canal = (canal & ~1) | bit
    Image.frombytes("RGB", img.size, bytes(date)).save(iesire, format="PNG")
    return len(biti)


# --------------------------------------------------------------------- B6
def dezvaluie(cale):
    """Citeste LSB-urile, le grupeaza cate 8 si reface mesajul pana la primul octet 0."""
    date = Image.open(cale).convert("RGB").tobytes()
    rezultat = bytearray()
    for i in range(0, len(date) - 7, 8):
        octet = 0
        for j in range(8):
            octet = (octet << 1) | (date[i + j] & 1)
        if octet == 0:
            break
        rezultat.append(octet)
    return bytes(rezultat)


def diferenta_maxima(a, b):
    """Cea mai mare diferenta dintre un octet de culoare din `a` si cel din `b`."""
    da = Image.open(a).convert("RGB").tobytes()
    db = Image.open(b).convert("RGB").tobytes()
    return max(abs(x - y) for x, y in zip(da, db))


def demo():
    gazda = os.path.join(RADACINA, "probe", "foto.jpg")
    iesire = os.path.join(RADACINA, "stego.png")
    n = ascunde(gazda, MESAJ, iesire)
    print(f"B5. ascuns: {MESAJ.decode()}  ({n} biti scrisi) -> stego.png")
    print("    diferenta maxima per canal fata de original:", diferenta_maxima(gazda, iesire),
          "(1 = invizibil cu ochiul liber)")
    print("B6. dezvaluit:", dezvaluie(iesire).decode())


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        demo()
    elif a[0] == "ascunde" and len(a) == 4:
        print(ascunde(a[1], a[2].encode(), a[3]), "biti scrisi")
    elif a[0] == "dezvaluie" and len(a) == 2:
        print(dezvaluie(a[1]).decode())
    else:
        print(__doc__)
