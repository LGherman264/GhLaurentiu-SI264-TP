# Laboratorul 6. Informații invizibile: forensics și steganografie

Disciplina: Tehnici de programare · st. gr. SI-264 Gherman Laurențiu · UTM, FCIM · 2026

## Sarcina lucrării

Construiesc două unelte de forensics în Python: un decoder universal (Lucrarea A: straturi de codare, XOR cu cheie de un octet, hash-uri sparte prin dicționar) și o suită de forensics pe fișiere plus steganografie LSB (Lucrarea B). Lucrez **doar** pe fișierele generate local de `probe/pregateste.py` și pe fișierele mele; forensics pe dispozitivul sau fișierele altcuiva, fără acord, este acces neautorizat la date (Cod penal RM, cap. XI).

## Rezultate (rezumat)

| Ce | Rezultat |
|---|---|
| Mesaj în straturi (mesaj.txt) | base64 → base64 → hex: FLAG{straturi_de_encoding} |
| XOR (xor.bin) | cheie 128 (0x80): FLAG{xor_un_octet} |
| Hash-uri (hashuri.txt) | md5: password, dragon, qwerty, letmein, monkey |
| Tipul real al fișierelor | foto.jpg = jpeg, ascuns.png = png, restul = text/binar fără semnătură |
| Metadate foto.jpg | Apple iPhone 13, 2026:09:14 10:30:00, GPS 47.0167 N, 28.8575 E (Chișinău) |
| Arhiva ascunsă (ascuns.png) | ZIP la octetul 781, secret.txt: FLAG{ascuns_prin_carving} |
| Mesaj LSB (stego.png) | FLAG{ascuns_in_pixeli} |
| challenge.bin (opțional) | base64 + XOR 0x80: FLAG{lant_complet_despicat} |

## Pregătirea mediului

**Pregătire.** Activez mediul virtual, instalez biblioteca de imagini (`pillow`, nu „PIL”) și `pytest`, creez folderele de lucru și rulez scriptul `probe/pregateste.py`, care generează în `probe/` toate țintele laboratorului.

*Figura 0.1 - Pregătirea mediului și generarea fișierelor de laborator*

```bash
source venv/bin/activate        # mediul virtual (Linux): in prompt apare (venv)
pip install pillow pytest
mkdir -p arsenal/forensics teste probe
python probe/pregateste.py       # scrie fisierele de laborator in probe/
```

Output:

```text
  scris: mesaj.txt
  scris: xor.bin
  scris: hashuri.txt
  scris: wordlist.txt
  scris: foto.jpg
  adaugat ZIP la coada: ascuns.png
  scris: challenge.bin
  scris: challenge_hint.txt
Gata. Tintele de laborator sunt in: ./probe
```

Scriptul este determinist (`random.seed(6)`), deci toate țintele sunt identice pentru toți studenții și repetabile. Lucrez doar pe aceste fișiere generate local.

## 1. Lucrarea A. Decoderul universal: arsenal/forensics/decode.py

**Exercițiul A1.** Text și octeți: încălzirea. Transform un șir în `bytes`, îi afișez forma hex și refac octeții cu `bytes.fromhex()`.

*Figura A.1 - Diferența dintre text și octeți (encode, hex, fromhex)*

```python
s = "Salut"
b = s.encode()          # bytes
print(b, b[0])          # b"Salut" 83
print(b.hex())          # reprezentarea hexazecimala
print(bytes.fromhex(b.hex()))   # refacem octetii din hex
```

Output:

```text
b'Salut' 83
53616c7574
b'Salut'
```

`b[0]` este un număr (83, codul literei S), nu o literă. Tot ce urmează lucrează pe `bytes`, nu pe text.

**Exercițiul A2.** Recunosc stratul după formă: funcția `ghici_strat(s)` clasifică un șir ca `url`, `hex`, `base64` sau `necunoscut`, fără să-l decodeze.

*Figura A.2 - Funcția ghici_strat(): clasificarea unui șir după alfabet*

```python
import re

def ghici_strat(s):
    if re.search(r"%[0-9A-Fa-f]{2}", s):
        return "url"
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s) and len(s) % 4 == 0:
        return "base64"
    return "necunoscut"

for t in ["%2Fetc", "48656c6c6f", "U2FsdXQ=", "Salut!"]:
    print(repr(t), "->", ghici_strat(t))
```

Output:

```text
'%2Fetc' -> url
'48656c6c6f' -> hex
'U2FsdXQ=' -> base64
'Salut!' -> necunoscut
```

Ordinea verificărilor contează: întâi `%` (URL), apoi hex (alfabet mai strict: doar 0-9 a-f și lungime pară), apoi base64 (cel mai larg alfabet, care include alfabetul hex). Dacă aș verifica base64 primul, un șir hex ar fi clasificat greșit.

**Exercițiul A3.** Desfac stratul recunoscut: `desfa(s)` decodează după verdictul din A2 și întoarce perechea `(strat, rezultat_bytes)`.

*Figura A.3 - Funcția desfa(): base64, hex și URL decodate*

```python
import base64
from urllib.parse import unquote

def desfa(s):
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

for t in ["%2Fetc", "48656c6c6f", "U2FsdXQ=", "Salut!"]:
    print(desfa(t))
```

Output:

```text
('url', b'/etc')
('hex', b'Hello')
('base64', b'Salut')
('necunoscut', b'Salut!')
```

Dacă șirul nu are o codare recunoscută sau decodarea eșuează, funcția întoarce `("necunoscut", s.encode())`, deci apelantul nu primește niciodată o excepție.

**Exercițiul A4.** Straturi multiple într-o buclă: decodez până nu mai găsesc nicio codare, cu o limită de 8 pași. Împachetez bucla în `desfa_straturi()`, care întoarce lista straturilor și rezultatul.

*Figura A.4 - Straturi multiple: mesaj.txt este base64 → base64 → hex*

```python
def citibil(b):
    return len(b) > 0 and all(32 <= c < 127 for c in b)


def desfa_straturi(val, max_pasi=8):
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


# --- bucla simpla, pas cu pas:
from arsenal.forensics.decode import desfa

val = open("probe/mesaj.txt").read().strip()
print("intrare:", val[:40] + "...")
for pas in range(1, 9):                   # maxim 8 pasi: fara bucla infinita
    strat, b = desfa(val)
    if strat == "necunoscut":             # nu mai e nicio codare: ne oprim
        print("rezultat final:", val)
        break
    print(f"pas {pas}: {strat:6s} -> {b.decode()[:50]}")
    val = b.decode()
```

Output:

```text
intrare: TkRZMFl6UXhORGMzWWpjek56UTNNall4TnpRM05U...
pas 1: base64 -> NDY0YzQxNDc3YjczNzQ3MjYxNzQ3NTcyNjk1ZjY0NjU1ZjY1Nm
pas 2: base64 -> 464c41477b73747261747572695f64655f656e636f64696e67
pas 3: hex    -> FLAG{straturi_de_encoding}
rezultat final: FLAG{straturi_de_encoding}
```

*Figura A.5 - desfa_straturi() pe mesaj.txt și pe exemplul din fișă*

```python
for val in [open("probe/mesaj.txt").read().strip(), "NTM1OTU3NTk="]:
    straturi, b = desfa_straturi(val)
    print(straturi, "->", b.decode())
```

Output:

```text
['base64', 'base64', 'hex'] -> FLAG{straturi_de_encoding}
['base64', 'hex'] -> SYWY
```

Capcană: după două decodări de base64 rămâne un șir hex, care este el însuși text imprimabil. Condiția din schelet („dacă `citibil(b)`, oprește”) s-ar opri deci prematur, la stratul hex. De aceea mă opresc când `ghici_strat` spune `necunoscut` (sau când rezultatul e un șir binar real), nu când octeții sunt doar imprimabili.

Ce ascundea mesajul cu straturi: `FLAG{straturi_de_encoding}`, ascuns sub trei straturi, base64 → base64 → hex.

**Exercițiul A5.** Sparg un XOR cu cheie de un octet: citesc `probe/xor.bin`, încerc toate cele 256 de chei și păstrez rezultatele care arată a text.

*Figura A.6 - Forța brută pe cele 256 de chei XOR*

```python
def citibil(b):
    return len(b) > 0 and all(32 <= c < 127 for c in b)


FRECVENTA = {...}   # frecventa literelor in engleza, vezi decode.py
NEUTRE = set(" _{}.,!-'")

def scor(clar):
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
    gasite = []
    for k in range(256):
        clar = bytes(b ^ k for b in date)
        if citibil(clar):
            gasite.append((k, clar))
    gasite.sort(key=lambda kc: scor(kc[1]), reverse=True)
    return gasite


date = open("probe/xor.bin", "rb").read()

# varianta din schelet: pastram orice rezultat "imprimabil"
simplu = [k for k in range(256) if citibil(bytes(b ^ k for b in date))]
print("chei care trec filtrul simplu:", len(simplu))

# varianta finala: le ordonam dupa scor (frecventa literelor), prima e cea mai probabila
for k, clar in xor_brute(date)[:3]:
    print("cheie:", k, hex(k), "->", clar.decode())
```

Output:

```text
chei care trec filtrul simplu: 17
cheie: 128 0x80 -> Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}
cheie: 129 0x81 -> To!rhofts!nbudu!uhod!unu!rdbsdutm///!f`rdrud,m !GM@Fzyns^to^nbudu|
cheie: 151 0x97 -> By7d~ypbe7xtcrc7c~yr7cxc7drtercb{9997pvdrdcr:{67Q[VPloxeHbyHxtcrcj
```

Filtrul „toți octeții imprimabili” nu lasă o singură cheie, ci mai multe: cheile vecine cu cea bună (0x81, 0x83 …) schimbă doar câțiva biți și lasă textul imprimabil, dar ilizibil. Le departajez cu un scor pe frecvența literelor (literele frecvente și spațiul cresc scorul, simbolurile ciudate îl scad).

Cheia XOR găsită: **128 (0x80)**. Textul clar: `Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}`.

**Exercițiul A6.** Sparg un hash prin dicționar: identific algoritmul după lungime, apoi hashuiesc fiecare cuvânt din `probe/wordlist.txt` și compar cu ținta. Generalizez în `sparge_hash()` și le sparg pe toate cele 5.

*Figura A.7 - Atac cu dicționar pe primul hash din hashuri.txt*

```python
import hashlib

tinta = open("probe/hashuri.txt").readline().strip()
print(tinta, "->", len(tinta), "caractere = md5")

for cuv in open("probe/wordlist.txt", encoding="latin1"):
    cuv = cuv.strip()
    if hashlib.md5(cuv.encode()).hexdigest() == tinta:
        print("gasit:", cuv)
        break
```

Output:

```text
5f4dcc3b5aa765d61d8327deb882cf99 -> 32 caractere = md5
gasit: password
```

*Figura A.8 - Funcția sparge_hash() aplicată pe toate hash-urile*

```python
import hashlib

ALGORITMI = {32: "md5", 40: "sha1", 64: "sha256"}

def sparge_hash(tinta, wordlist=WORDLIST):
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


for h in open("probe/hashuri.txt").read().split():
    algo, parola = sparge_hash(h)
    print(h, f"[{algo}]", "->", parola)
```

Output:

```text
5f4dcc3b5aa765d61d8327deb882cf99 [md5] -> password
8621ffdbc5698829397d97767ac13db3 [md5] -> dragon
d8578edf8458ce06fbc5bb76a58c5ca4 [md5] -> qwerty
0d107d09f5bbe40cade3de5c71e9e9b7 [md5] -> letmein
d0763edaa9d9bd2a9516280e9044d885 [md5] -> monkey
```

Nu „decriptez” hash-ul, ci hashuiesc fiecare cuvânt și compar. Lungimea îmi spune algoritmul: 32 = md5, 40 = sha1, 64 = sha256. Toate cele cinci hash-uri sunt md5.

Parolele sparte: `password`, `dragon`, `qwerty`, `letmein`, `monkey`.

**Exercițiul A7.** `argparse`, fișa JSON și un test: leg totul într-o unealtă de linie de comandă, salvez rezultatul în `arsenal/forensics/fisa.json` și scriu teste.

*Figura A.9 - Funcția main(): argparse, moduri de lucru și salvarea fișei*

```python
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
```

*Figura A.10 - Rularea unealtei din linia de comandă*

```bash
python arsenal/forensics/decode.py "U2FsdXQ="
python arsenal/forensics/decode.py probe/mesaj.txt --fisier
python arsenal/forensics/decode.py probe/xor.bin --fisier --xor
python arsenal/forensics/decode.py probe/hashuri.txt --fisier --hash
```

Output:

```text
$ python arsenal/forensics/decode.py "U2FsdXQ="
straturi: base64
rezultat: Salut
fisa salvata in: arsenal/forensics/fisa.json

$ python arsenal/forensics/decode.py probe/mesaj.txt --fisier
straturi: base64 -> base64 -> hex
rezultat: FLAG{straturi_de_encoding}
fisa salvata in: arsenal/forensics/fisa.json

$ python arsenal/forensics/decode.py probe/xor.bin --fisier --xor
17 chei lasa text imprimabil; cea mai probabila e prima:
cheie: 128 (0x80) -> Un singur octet tine tot secretul... gaseste-l! FLAG{xor_un_octet}
cheie: 129 (0x81) -> To!rhofts!nbudu!uhod!unu!rdbsdutm///!f`rdrud,m !GM@Fzyns^to^nbudu|
cheie: 151 (0x97) -> By7d~ypbe7xtcrc7c~yr7cxc7drtercb{9997pvdrdcr:{67Q[VPloxeHbyHxtcrcj
fisa salvata in: arsenal/forensics/fisa.json

$ python arsenal/forensics/decode.py probe/hashuri.txt --fisier --hash
5f4dcc3b5aa765d61d8327deb882cf99  [md5]  ->  password
8621ffdbc5698829397d97767ac13db3  [md5]  ->  dragon
d8578edf8458ce06fbc5bb76a58c5ca4  [md5]  ->  qwerty
0d107d09f5bbe40cade3de5c71e9e9b7  [md5]  ->  letmein
d0763edaa9d9bd2a9516280e9044d885  [md5]  ->  monkey
fisa salvata in: arsenal/forensics/fisa.json
```

*Figura A.11 - Fișa arsenal/forensics/fisa.json salvată pentru mesaj.txt*

```bash
cat arsenal/forensics/fisa.json
```

Output:

```text
{
  "intrare": "probe/mesaj.txt",
  "strat": "base64 -> base64 -> hex",
  "straturi": [
    "base64",
    "base64",
    "hex"
  ],
  "rezultat": "FLAG{straturi_de_encoding}"
}
```

*Figura A.12 - Testele din teste/test_decode.py (cod)*

```python
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
```

*Figura A.13 - Rularea testelor*

```bash
python teste/test_decode.py
```

Output:

```text
PASS test_base64
PASS test_citibil
PASS test_exemplul_din_fisa
PASS test_fisiere_de_proba
PASS test_hash_dictionar
PASS test_hex
PASS test_necunoscut
PASS test_straturi_multiple
PASS test_url
PASS test_xor_cheia_buna_prima
PASS test_xor_un_octet
toate testele au trecut
```

Intrarea se tratează ca șir sau, cu `--fisier`, ca octeți citiți din cale. Blocul `if __name__ == "__main__":` este esențial: fără el, `argparse` ar rula la importul din teste și ar strica `from arsenal.forensics.decode import desfa`.

Testele se pot rula și cu `python -m pytest -v` din rădăcina depozitului (pentru care am instalat `pytest`).

## 2. Lucrarea B. Forensics pe fișiere și steganografie

**Exercițiul B1.** Magic bytes: citesc primii octeți ai fișierului (în mod `"rb"`) și îi compar cu semnăturile cunoscute, ca să aflu tipul real, nu cel din extensie.

*Figura B.1 - Funcția tip_real(): tipul real după magic bytes*

```python
SEMNATURI = [(b"%PDF", "pdf"), (b"\x89PNG", "png"), (b"\xff\xd8", "jpeg"),
              (b"PK\x03\x04", "zip/docx"), (b"GIF8", "gif")]

def tip_real(cale):
    with open(cale, "rb") as f:
        cap = f.read(8)
    for semnatura, nume in SEMNATURI:
        if cap.startswith(semnatura):
            return nume
    if all(32 <= c < 127 or c in (9, 10, 13) for c in cap):
        return "text"  # fara semnatura, dar doar caractere imprimabile
    return cap.hex()  # necunoscut: intoarcem octetii in hex

for nume in ["foto.jpg", "ascuns.png", "mesaj.txt", "xor.bin"]:
    print(f"{nume:12s} ->", tip_real("probe/" + nume))
```

Output:

```text
foto.jpg     -> jpeg
ascuns.png   -> png
mesaj.txt    -> text
xor.bin      -> d5eea0f3e9eee7f5
```

`foto.jpg` începe cu `FF D8` (jpeg), iar `ascuns.png` cu `89 50 4E 47` (png). Fișierele text nu au semnătură, așa că funcția întoarce `text`, iar `xor.bin`, cu octeți binari fără semnătură cunoscută, rămâne cu primii 8 octeți în hex. Modul `"rb"` nu e opțional pentru fișiere binare: fără el, octeții se pot altera.

**Exercițiul B2.** `strings`: scot secvențele de caractere imprimabile dintr-un binar cu un regex pe octeți (`rb"[ -~]{4,}"`).

*Figura B.2 - strings pe probe/ascuns.png*

```python
import re

def strings(cale, minim=4):
    with open(cale, "rb") as f:
        date = f.read()
    return [m.decode() for m in re.findall(rb"[ -~]{%d,}" % minim, date)]

for s in strings("probe/ascuns.png"):
    print(repr(s))
```

Output:

```text
'IHDR'
'IDATx'
'15hB'
'IEND'
'secret.txtFLAG{ascuns_prin_carving}'
'secret.txtPK'
```

Printre resturile formatului PNG (`IDAT`) apare numele `secret.txt` și chiar conținutul lui, `FLAG{ascuns_prin_carving}`, deci în fișier se ascunde o arhivă. Arhiva e stocată necomprimat, de aceea textul se vede în clar.

**Exercițiul B3.** Metadate EXIF și GPS: citesc blocul EXIF din `probe/foto.jpg`, scot blocul GPS (tag 34853) și convertesc coordonatele din grade/minute/secunde în grade zecimale.

*Figura B.3 - Tag-urile EXIF și blocul GPS brut*

```python
from PIL import Image
from PIL.ExifTags import TAGS

exif = Image.open("probe/foto.jpg").getexif()
for id, val in exif.items():
    print(TAGS.get(id, id), "=", val)
print("bloc GPS (tag 34853):", dict(exif.get_ifd(34853)))
```

Output:

```text
Model = iPhone 13
DateTime = 2026:09:14 10:30:00
GPSInfo = 98
Make = Apple
bloc GPS (tag 34853): {1: 'N', 2: (47.0, 1.0, 0.0), 3: 'E', 4: (28.0, 51.0, 27.0)}
```

*Figura B.4 - Conversia coordonatelor GPS în grade zecimale*

```python
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS

def dms_la_zecimal(dms, ref):
    grade, minute, secunde = (float(x) for x in dms)
    val = grade + minute / 60 + secunde / 3600
    return -val if ref in ("S", "W") else val


def exif(cale):
    ex = Image.open(cale).getexif()
    return {TAGS.get(id_, id_): val for id_, val in ex.items() if id_ != 34853}


def gps(cale):
    bloc = Image.open(cale).getexif().get_ifd(34853)  # 34853 = 0x8825 = GPSInfo
    if not bloc:
        return None
    g = {GPSTAGS.get(k, k): v for k, v in bloc.items()}
    lat = dms_la_zecimal(g["GPSLatitude"], g["GPSLatitudeRef"])
    lon = dms_la_zecimal(g["GPSLongitude"], g["GPSLongitudeRef"])
    return lat, lon

print(exif("probe/foto.jpg"))
lat, lon = gps("probe/foto.jpg")
print(f"lat = {lat:.4f}, lon = {lon:.4f}")
print(f"https://www.openstreetmap.org/?mlat={lat:.4f}&mlon={lon:.4f}&zoom=14")
```

Output:

```text
{'Model': 'iPhone 13', 'DateTime': '2026:09:14 10:30:00', 'Make': 'Apple'}
lat = 47.0167, lon = 28.8575
https://www.openstreetmap.org/?mlat=47.0167&mlon=28.8575&zoom=14
```

Metadate găsite: producător **Apple**, model **iPhone 13**, data **2026:09:14 10:30:00**. GPS: 47° 1′ 0″ N, 28° 51′ 27″ E, adică grade zecimale **47.0167 N, 28.8575 E** (lat = 47 + 1/60, lon = 28 + 51/60 + 27/3600), un punct în **Chișinău**.

Valoarea pentru OSINT: dintr-o simplă poză se poate afla unde și când a fost făcută, ceea ce justifică ștergerea EXIF înainte de a publica o imagine.

**Exercițiul B4.** File carving: `probe/ascuns.png` are o arhivă ZIP lipită la coadă. Caut semnătura `PK\x03\x04`, salvez de acolo până la capăt ca `gasit.zip` și o dezarhivez.

*Figura B.5 - File carving: arhiva ZIP extrasă din ascuns.png*

```python
import zipfile

def carve_zip(cale, iesire="gasit.zip"):
    with open(cale, "rb") as f:
        date = f.read()
    i = date.find(b"PK\x03\x04")
    if i != -1:
        with open(iesire, "wb") as f:
            f.write(date[i:])
    return i

i = carve_zip("probe/ascuns.png", "gasit.zip")
print("arhiva extrasa de la octetul", i)
with zipfile.ZipFile("gasit.zip") as z:
    for info in z.infolist():
        print("in arhiva:", info.filename, f"({info.file_size} octeti)")
        print("continut:", z.read(info).decode().strip())
```

Output:

```text
arhiva extrasa de la octetul 781
in arhiva: secret.txt (26 octeti)
continut: FLAG{ascuns_prin_carving}
```

Semnătura ZIP se găsește la octetul 781. Imaginea se deschide normal ca PNG, pentru că vizualizatoarele se opresc la finalul datelor PNG, iar octeții de după sunt ignorați. Arhiva conține `secret.txt` cu textul **FLAG{ascuns_prin_carving}**.

**Exercițiul B5.** Ascund un mesaj prin LSB: scriu biții mesajului în ultimul bit al fiecărui octet de culoare (R, G, B, R, G, B …) și salvez în PNG.

*Figura B.6 - Ascunderea mesajului în ultimii biți ai pixelilor (stego.png)*

```python
from PIL import Image

def ascunde(sursa, mesaj, iesire):
    img = Image.open(sursa).convert("RGB")
    date = bytearray(img.tobytes())          # R,G,B,R,G,B,... cate un octet pe canal
    biti = "".join(f"{x:08b}" for x in mesaj + b"\x00")   # \x00 = final de mesaj
    if len(biti) > len(date):
        raise ValueError(f"mesaj prea lung: {len(biti)} biti, capacitate {len(date)}")
    for i, bit in enumerate(biti):
        date[i] = (date[i] & ~1) | int(bit)  # canal = (canal & ~1) | bit
    Image.frombytes("RGB", img.size, bytes(date)).save(iesire, format="PNG")
    return len(biti)


def diferenta_maxima(a, b):
    da = Image.open(a).convert("RGB").tobytes()
    db = Image.open(b).convert("RGB").tobytes()
    return max(abs(x - y) for x, y in zip(da, db))

n = ascunde("probe/foto.jpg", b"FLAG{ascuns_in_pixeli}", "stego.png")
print("biti scrisi:", n, "-> stego.png")
print("diferenta maxima per canal fata de original:", diferenta_maxima("probe/foto.jpg", "stego.png"))
```

Output:

```text
biti scrisi: 184 -> stego.png
diferenta maxima per canal fata de original: 1
```

Pentru fiecare bit aplic `canal = (canal & ~1) | bit`, deci un canal se schimbă cu cel mult 1 din 255 (diferența maximă măsurată: 1), invizibil cu ochiul liber. Adaug un octet `0` la final, ca marcaj de sfârșit de mesaj. Salvez în `.png` (fără pierderi): un `.jpg` ar recomprima imaginea și ar distruge biții ascunși.

**Exercițiul B6.** Dezvăluiesc mesajul înapoi: citesc ultimii biți ai pixelilor din `stego.png`, îi grupez câte 8 în octeți și mă opresc la primul octet `0`.

*Figura B.7 - Dezvăluirea mesajului LSB din stego.png*

```python
def dezvaluie(cale):
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

print("mesaj dezvaluit:", dezvaluie("stego.png").decode())
```

Output:

```text
mesaj dezvaluit: FLAG{ascuns_in_pixeli}
```

Dezvăluirea este exact inversul ascunderii. Mesajul LSB dezvăluit: **FLAG{ascuns_in_pixeli}**.

## 3. Vârful sălii (opțional): challenge.bin

**Provocare.** Despic `probe/challenge.bin`, fără schelet: un strat de base64 peste un XOR cu cheie de un octet, cu un md5 dat ca verificare în `challenge_hint.txt`.

*Figura C.1 - challenge.py: base64, apoi XOR, verificat cu md5-ul din indiciu*

```python
import base64
import hashlib
import os
import re

from arsenal.forensics.decode import xor_brute

PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probe")

hint = open(os.path.join(PROBE, "challenge_hint.txt"), encoding="utf-8").read()
md5_asteptat = re.search(r"[0-9a-f]{32}", hint).group()
print("md5 asteptat:", md5_asteptat)

strat1 = base64.b64decode(open(os.path.join(PROBE, "challenge.bin")).read())
print("dupa base64:", strat1.hex())

for cheie, clar in xor_brute(strat1):
    ok = hashlib.md5(clar).hexdigest() == md5_asteptat
    if ok:
        print(f"cheie XOR: {cheie} (0x{cheie:02x})")
        print("text clar:", clar.decode())
        print("md5 verificat: da")
        break
else:
    print("nicio cheie nu se potriveste cu md5-ul")
```

Output:

```text
md5 asteptat: 8c4eb02d9dcef7d0ff91d8e4c7fea91b
dupa base64: c6ccc1c7fbece1eef4dfe3efedf0ece5f4dfe4e5f3f0e9e3e1f4fd
cheie XOR: 128 (0x80)
text clar: FLAG{lant_complet_despicat}
md5 verificat: da
```

*Figura C.2 - Același lanț, desfăcut automat de decode.py*

```bash
python arsenal/forensics/decode.py probe/challenge.bin --fisier
```

Output:

```text
straturi: base64 -> xor(cheie=128)
rezultat: FLAG{lant_complet_despicat}
fisa salvata in: arsenal/forensics/fisa.json
```

Pașii: (1) indiciul spune ce straturi sunt și dă md5-ul textului clar; (2) decodez base64 și obțin octeți binari, deci nu mai e text; (3) încerc toate cele 256 de chei XOR și o aleg pe cea pentru care `md5(clar)` coincide cu cel din indiciu. Cheia este 128 (0x80), iar textul clar este **FLAG{lant_complet_despicat}**.

## Concluzie

Am construit un decoder universal care recunoaște și desface straturi de codare (base64, hex, URL), sparge un XOR cu cheie de un octet și hash-uri md5 prin dicționar, și un set de unelte de forensics pe fișiere: tip real după magic bytes, `strings`, metadate EXIF cu GPS, file carving și steganografie LSB. Lecția principală: un fișier spune mai mult decât pare (extensia minte, semnătura nu; o poză trădează locul și momentul), iar „ascuns” nu înseamnă „protejat”. Aceleași unelte sunt legale doar pe ce îmi aparține.
