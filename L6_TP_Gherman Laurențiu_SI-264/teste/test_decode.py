# -*- coding: utf-8 -*-
# Rulare (din radacina depozitului):  python -m pytest -v
import os
import sys

RADACINA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RADACINA)  # ca sa mearga si cu: python teste/test_decode.py

from arsenal.forensics.decode import (
    citibil, desfa, desfa_straturi, ghici_strat, sparge_hash, xor_brute,
)

PROBE = os.path.join(RADACINA, "probe")


def test_base64():
    strat, b = desfa("U2FsdXQ=")
    assert strat == "base64"
    assert b == b"Salut"


def test_hex():
    assert ghici_strat("48656c6c6f") == "hex"
    assert desfa("48656c6c6f") == ("hex", b"Hello")


def test_url():
    assert ghici_strat("%2Fetc") == "url"
    assert desfa("%2Fetc") == ("url", b"/etc")


def test_necunoscut():
    assert ghici_strat("Salut!") == "necunoscut"


def test_citibil():
    assert citibil(b"abc 123")
    assert not citibil(b"\x00abc")
    assert not citibil(b"")


def test_straturi_multiple():
    # base64(base64(hex("Hi"))) -> trei straturi
    import base64
    val = base64.b64encode(base64.b64encode(b"4869")).decode()
    straturi, b = desfa_straturi(val)
    assert straturi == ["base64", "base64", "hex"]
    assert b == b"Hi"


def test_exemplul_din_fisa():
    # "NTM1OTU3NTk=" -> base64 -> "53595759" -> hex -> "SYWY" (apoi se opreste)
    straturi, b = desfa_straturi("NTM1OTU3NTk=")
    assert straturi == ["base64", "hex"]
    assert b == b"SYWY"


def test_xor_un_octet():
    clar = b"Text de test"
    cript = bytes(c ^ 0x80 for c in clar)
    assert (0x80, clar) in xor_brute(cript)


def test_xor_cheia_buna_prima():
    # cheile vecine (0x81, 0x83...) lasa si ele text imprimabil; scorul o alege pe cea corecta
    clar = b"Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}"
    cript = bytes(c ^ 0x80 for c in clar)
    gasite = xor_brute(cript)
    assert len(gasite) > 1
    assert gasite[0] == (0x80, clar)


def test_hash_dictionar():
    # md5("password") cu un wordlist propriu
    wl = os.path.join(PROBE, "wordlist.txt")
    if not os.path.exists(wl):
        return  # fisierele de proba nu au fost generate inca
    assert sparge_hash("5f4dcc3b5aa765d61d8327deb882cf99", wl) == ("md5", "password")


def test_fisiere_de_proba():
    mesaj = os.path.join(PROBE, "mesaj.txt")
    if not os.path.exists(mesaj):
        return
    straturi, b = desfa_straturi(open(mesaj).read().strip())
    assert straturi == ["base64", "base64", "hex"]
    assert b.startswith(b"FLAG{")


if __name__ == "__main__":
    # rulare simpla, fara pytest:  python teste/test_decode.py
    esuate = 0
    for nume, f in sorted(globals().items()):
        if nume.startswith("test_") and callable(f):
            try:
                f()
                print("PASS", nume)
            except AssertionError:
                esuate += 1
                print("FAIL", nume)
    print("toate testele au trecut" if not esuate else f"{esuate} teste esuate")
    sys.exit(1 if esuate else 0)
