# -*- coding: utf-8 -*-
"""Decoder universal - Laboratorul 6, Lucrarea A.

Primeste un sir (sau un fisier), recunoaste stratul de codare (url / hex / base64),
il desface, repeta pana nu mai gaseste straturi. Poate sparge, de asemenea:
  * un XOR cu cheie de un octet (forta bruta pe cele 256 de chei);
  * un hash de parola (md5 / sha1 / sha256) printr-un atac cu dictionar.

Exemple (din radacina depozitului):
    python arsenal/forensics/decode.py probe/mesaj.txt --fisier
    python arsenal/forensics/decode.py probe/xor.bin --fisier --xor
    python arsenal/forensics/decode.py probe/hashuri.txt --fisier --hash
    python arsenal/forensics/decode.py "U2FsdXQ="
"""

import argparse
import base64
import hashlib
import json
import os
import re
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
RADACINA = os.path.dirname(os.path.dirname(HERE))
FISA = os.path.join(HERE, "fisa.json")
WORDLIST = os.path.join(RADACINA, "probe", "wordlist.txt")

# lungimea hash-ului (in caractere hex) -> algoritm
ALGORITMI = {32: "md5", 40: "sha1", 64: "sha256"}


# ---------------------------------------------------------------- A4 / A5
def citibil(b):
    """True daca toti octetii sunt caractere imprimabile ASCII (32..126)."""
    return len(b) > 0 and all(32 <= c < 127 for c in b)


# --------------------------------------------------------------------- A2
def ghici_strat(s):
    """Ghiceste codarea unui sir dupa forma lui (fara sa-l decodeze).

    Ordinea conteaza: URL (are '%xx'), apoi hex (alfabet mai strict),
    apoi base64 (cel mai larg alfabet).
    """
    if re.search(r"%[0-9A-Fa-f]{2}", s):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(s) % 4 == 0:
        return "base64"
    return "necunoscut"


# --------------------------------------------------------------------- A3
def desfa(s):
    """Desface un strat. Intoarce (strat, rezultat_bytes).

    Daca sirul nu are o codare recunoscuta (sau nu se poate decoda),
    intoarce ("necunoscut", s.encode()).
    """
    strat = ghici_strat(s)
    try:
        if strat == "base64":
            return strat, base64.b64decode(s, validate=True)
        if strat == "hex":
            return strat, bytes.fromhex(s)
        if strat == "url":
            return strat, unquote(s).encode()
    except ValueError:  # binascii.Error este subclasa a lui ValueError
        pass
    return "necunoscut", s.encode()


# --------------------------------------------------------------------- A4
def desfa_straturi(val, max_pasi=8):
    """Desface straturile in bucla. Intoarce (lista_straturi, rezultat_bytes).

    Atentie: un strat hex decodat este el insusi text imprimabil, deci nu ne
    putem opri doar pentru ca rezultatul e "citibil". Ne oprim cand ghici_strat
    spune "necunoscut", cand rezultatul nu mai e text (octeti binari) sau cand
    s-au epuizat max_pasi (ca sa nu intram in bucla infinita).
    """
    straturi = []
    curent = val.encode() if isinstance(val, str) else bytes(val)
    for _ in range(max_pasi):
        try:
            text = curent.decode("ascii").strip()
        except UnicodeDecodeError:
            break  # octeti binari: nu mai e un sir de desfacut
        strat, b = desfa(text)
        if strat == "necunoscut" or not b:
            break
        if not citibil(b) and len(b) < 8:
            break  # prea scurt ca sa fie binar adevarat: probabil un cuvant, nu o codare
        straturi.append(strat)
        curent = b
    return straturi, curent


# --------------------------------------------------------------------- A5
# frecventa aproximativa a literelor in engleza (procente); spatiul e cel mai des
FRECVENTA = {
    "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7, "s": 6.3,
    "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8, "u": 2.8, "m": 2.4,
    "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0, "p": 1.9, "b": 1.5, "v": 1.0,
    "k": 0.8, "j": 0.15, "x": 0.15, "q": 0.1, "z": 0.07, " ": 18.0,
}
NEUTRE = set(" _{}.,!-'")


def scor(clar):
    """Cat de mult seamana un text cu limbaj natural (frecventa literelor).

    Filtrul "toti octetii imprimabili" nu e suficient: o cheie vecina cu cea
    buna (ex. 0x81 in loc de 0x80) schimba doar un bit si lasa tot imprimabil.
    Scorul aduna frecventa fiecarei litere, ignora cifrele si semnele uzuale
    (_ { } . , ! - ') si penalizeaza restul, deci cheia corecta iese prima.
    """
    total = 0.0
    for c in clar:
        ch = chr(c).lower()
        if ch in FRECVENTA:
            total += FRECVENTA[ch]
        elif ch.isdigit() or ch in NEUTRE:
            pass
        else:
            total -= 10
    return total


def xor_brute(date):
    """Incearca toate cele 256 de chei de un octet. Intoarce [(cheie, clar), ...]
    pentru rezultatele imprimabile, cele mai probabile (scor mare) primele."""
    gasite = []
    for k in range(256):
        clar = bytes(b ^ k for b in date)
        if citibil(clar):
            gasite.append((k, clar))
    gasite.sort(key=lambda kc: scor(kc[1]), reverse=True)
    return gasite


# --------------------------------------------------------------------- A6
def sparge_hash(tinta, wordlist=WORDLIST):
    """Atac cu dictionar. Intoarce (algoritm, parola) sau (algoritm, None).

    Nu "decriptam" hash-ul: hashuim fiecare cuvant si comparam.
    """
    tinta = tinta.strip().lower()
    algo = ALGORITMI.get(len(tinta))
    if algo is None:
        return None, None
    with open(wordlist, encoding="latin1") as f:
        for cuv in f:
            cuv = cuv.strip()
            if hashlib.new(algo, cuv.encode()).hexdigest() == tinta:
                return algo, cuv
    return algo, None


# --------------------------------------------------------------------- A7
def salveaza_fisa(fisa, cale=FISA):
    with open(cale, "w", encoding="utf-8") as f:
        json.dump(fisa, f, indent=2, ensure_ascii=False)
    return cale


def main(argv=None):
    p = argparse.ArgumentParser(description="Decoder universal: straturi, XOR, hash.")
    p.add_argument("intrare", help="un sir sau (cu --fisier) calea unui fisier")
    p.add_argument("--fisier", action="store_true", help="intrarea este o cale de fisier")
    p.add_argument("--xor", action="store_true", help="sparge un XOR cu cheie de un octet")
    p.add_argument("--hash", action="store_true", help="sparge hash-uri prin dictionar")
    p.add_argument("--wordlist", default=WORDLIST, help="fisierul cu cuvinte (pentru --hash)")
    p.add_argument("--fisa", default=FISA, help="unde se salveaza fisa JSON")
    a = p.parse_args(argv)

    # intrarea: octeti din fisier sau sirul din linia de comanda
    if a.fisier:
        with open(a.intrare, "rb") as f:
            octeti = f.read()
    else:
        octeti = a.intrare.encode()

    if a.xor:
        gasite = xor_brute(octeti)
        print(f"{len(gasite)} chei lasa text imprimabil; cea mai probabila e prima:")
        for k, clar in gasite[:3]:
            print("cheie:", k, "(0x%02x)" % k, "->", clar.decode())
        fisa = {
            "intrare": a.intrare,
            "strat": "xor (cheie de un octet)",
            "cheie": gasite[0][0] if gasite else None,
            "rezultat": gasite[0][1].decode() if gasite else None,
        }
    elif a.hash:
        linii = octeti.decode().split() if a.fisier else [a.intrare]
        rez = {}
        for h in linii:
            algo, parola = sparge_hash(h, a.wordlist)
            rez[h] = {"algoritm": algo, "parola": parola}
            print(f"{h}  [{algo}]  ->  {parola if parola else 'negasit'}")
        fisa = {"intrare": a.intrare, "strat": "hash (dictionar)", "rezultat": rez}
    else:
        straturi, b = desfa_straturi(octeti.decode("ascii", "replace").strip())
        if straturi and not citibil(b):
            # ultimul strat a dat octeti binari: poate e un XOR cu cheie de un octet
            gasite = xor_brute(b)
            if gasite:
                k, b = gasite[0]
                straturi.append(f"xor(cheie={k})")
        print("straturi:", " -> ".join(straturi) if straturi else "(niciunul)")
        text = b.decode("utf-8", "replace")
        print("rezultat:", text)
        fisa = {
            "intrare": a.intrare,
            "strat": " -> ".join(straturi) if straturi else "necunoscut",
            "straturi": straturi,
            "rezultat": text,
        }

    print("fisa salvata in:", os.path.relpath(salveaza_fisa(fisa, a.fisa)))


if __name__ == "__main__":
    main()
