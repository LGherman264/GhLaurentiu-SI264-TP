# -*- coding: utf-8 -*-
"""Forensics pe fisiere - Laboratorul 6, Lucrarea B (B1-B4).

B1  tip_real      - tipul real dupa magic bytes, nu dupa extensie
B2  strings       - textul citibil dintr-un binar
B3  exif / gps    - metadate EXIF si coordonate GPS in grade zecimale
B4  carve_zip     - extrage arhiva ZIP lipita la coada unei imagini

Rulare (din radacina depozitului):   python forensics.py
Tinte permise: doar fisierele din probe/ (generate de probe/pregateste.py).
"""

import os
import re
import zipfile

from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

RADACINA = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(RADACINA, "probe")

# (semnatura de la inceputul fisierului, tip)
SEMNATURI = [
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8", "jpeg"),
    (b"PK\x03\x04", "zip/docx"),
    (b"GIF8", "gif"),
]


# --------------------------------------------------------------------- B1
def tip_real(cale):
    """Tipul real al fisierului, dupa primii octeti ("rb": fisier binar)."""
    with open(cale, "rb") as f:
        cap = f.read(8)
    for semnatura, nume in SEMNATURI:
        if cap.startswith(semnatura):
            return nume
    if all(32 <= c < 127 or c in (9, 10, 13) for c in cap):
        return "text"  # fara semnatura, dar doar caractere imprimabile
    return cap.hex()  # necunoscut: intoarcem octetii in hex


# --------------------------------------------------------------------- B2
def strings(cale, minim=4):
    """Toate secventele de caractere imprimabile (ASCII) de cel putin `minim` caractere."""
    with open(cale, "rb") as f:
        date = f.read()
    return [m.decode() for m in re.findall(rb"[ -~]{%d,}" % minim, date)]


# --------------------------------------------------------------------- B3
def dms_la_zecimal(dms, ref):
    """(grade, minute, secunde) + emisfera (N/S/E/W) -> grade zecimale."""
    grade, minute, secunde = (float(x) for x in dms)
    val = grade + minute / 60 + secunde / 3600
    return -val if ref in ("S", "W") else val


def exif(cale):
    """Metadatele EXIF ca dictionar {nume_tag: valoare} (fara blocul GPS)."""
    ex = Image.open(cale).getexif()
    return {TAGS.get(id_, id_): val for id_, val in ex.items() if id_ != 34853}


def gps(cale):
    """Coordonatele GPS ca (lat, lon) in grade zecimale, sau None daca nu exista."""
    bloc = Image.open(cale).getexif().get_ifd(34853)  # 34853 = 0x8825 = GPSInfo
    if not bloc:
        return None
    g = {GPSTAGS.get(k, k): v for k, v in bloc.items()}
    lat = dms_la_zecimal(g["GPSLatitude"], g["GPSLatitudeRef"])
    lon = dms_la_zecimal(g["GPSLongitude"], g["GPSLongitudeRef"])
    return lat, lon


# --------------------------------------------------------------------- B4
def carve_zip(cale, iesire="gasit.zip"):
    """Cauta semnatura ZIP in fisier si salveaza tot ce urmeaza ca arhiva separata.

    Intoarce offsetul la care a gasit-o, sau -1 daca nu exista.
    """
    with open(cale, "rb") as f:
        date = f.read()
    i = date.find(b"PK\x03\x04")
    if i != -1:
        with open(iesire, "wb") as f:
            f.write(date[i:])
    return i


def main():
    print("== B1. Magic bytes: tipul real ==")
    for nume in sorted(os.listdir(PROBE)):
        cale = os.path.join(PROBE, nume)
        if nume.endswith(".py"):
            continue
        print(f"  {nume:20s} extensie: {os.path.splitext(nume)[1]:5s} tip real: {tip_real(cale)}")

    print("\n== B2. strings pe probe/ascuns.png (cele mai relevante) ==")
    siruri = strings(os.path.join(PROBE, "ascuns.png"))
    for s in siruri:
        if s.isupper() and len(s) <= 4 and s != "FLAG":
            continue  # zgomot: numele chunk-urilor PNG (IHDR, IDAT...)
        print("  ", s)

    print("\n== B3. EXIF si GPS din probe/foto.jpg ==")
    foto = os.path.join(PROBE, "foto.jpg")
    for tag, val in exif(foto).items():
        print(f"  {tag} = {val}")
    lat, lon = gps(foto)
    print(f"  GPS: lat = {lat:.4f}, lon = {lon:.4f}")
    print(f"  Harta: https://www.openstreetmap.org/?mlat={lat:.4f}&mlon={lon:.4f}&zoom=14")

    print("\n== B4. File carving din probe/ascuns.png ==")
    ascuns = os.path.join(PROBE, "ascuns.png")
    i = carve_zip(ascuns, "gasit.zip")
    if i == -1:
        print("  nicio arhiva ZIP gasita")
        return
    print("  arhiva extrasa de la octetul", i)
    with zipfile.ZipFile("gasit.zip") as z:
        for info in z.infolist():
            print(f"  in arhiva: {info.filename} ({info.file_size} octeti)")
            print("  continut:", z.read(info).decode().strip())


if __name__ == "__main__":
    main()
