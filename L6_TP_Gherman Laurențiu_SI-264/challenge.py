# -*- coding: utf-8 -*-
"""Varful salii (optional): despica probe/challenge.bin fara schelet.

Pasii:
  1. challenge_hint.txt zice: un strat base64 peste un XOR cu cheie de un octet,
     iar md5 al textului clar este dat ca verificare.
  2. Stratul exterior: base64 -> octeti binari (nu mai sunt text, deci e XOR).
  3. XOR: incercam toate cele 256 de chei; verificam fiecare candidat cu md5-ul din indiciu.
"""

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
